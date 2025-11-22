from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError

from .dashboard import Dashboard
from .types.common import CollectionName


class DashboardRepository:
    """
    Repository for Dashboard persistence in MongoDB.

    :ivar collection: MongoDB collection for dashboards
    :vartype collection: Collection
    """

    def __init__(self, db: Database, collection_name: str = "dashboards"):
        """
        Initialize repository with MongoDB database.

        :param db: PyMongo database instance
        :type db: Database
        :param collection_name: Name of collection for dashboards (default: "dashboards")
        :type collection_name: str
        """
        self.collection: Collection = db[collection_name]
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        """Create required indexes.

        - Index on user_id for fast lookups
        - Unique partial index on (user_id, collection_name) on default dashboards
        - Index on created_at for sorting and date queries

        """
        self.collection.create_index("user_id")

        self.collection.create_index(
            [("user_id", 1), ("collection_name", 1), ("is_default", 1)],
            unique=True,
            partialFilterExpression={"is_default": True},
        )

        self.collection.create_index([("created_at", -1)])

    def save(self, dashboard: Dashboard) -> str:
        """
        Save dashboard to MongoDB (insert or update).

        :param dashboard: Dashboard to save
        :type dashboard: Dashboard

        :return: Dashboard ID (unchanged)
        :rtype: str

        :raises PyMongoError: If database operation fails
        """
        serialized_dashboard = dashboard.to_dict()

        dashboard_id = serialized_dashboard.pop("dashboard_id")

        try:
            if dashboard.is_default:
                self.collection.update_many(
                    {
                        "user_id": dashboard.user_id,
                        "collection_name": dashboard.collection_name,
                        "is_default": True,
                        "dashboard_id": {"$ne": dashboard_id},  # Skip if updating itself
                    },
                    {"$set": {"is_default": False}},
                )

            self.collection.update_one(
                {"dashboard_id": dashboard_id},
                {"$set": serialized_dashboard},
                upsert=True,
            )

            return dashboard_id

        except PyMongoError as e:
            raise PyMongoError(f"Failed to save dashboard.\n{serialized_dashboard}") from e

    def get_by_id(self, dashboard_id: str) -> Dashboard | None:
        """
        Retrieve dashboard by ID.

        :param dashboard_id: Dashboard ID to retrieve
        :type dashboard_id: str

        :return: Dashboard if found, None otherwise
        :rtype: Dashboard or None

        :raises ValueError: If dashboard data is corrupted/invalid
        """
        doc = self.collection.find_one({"dashboard_id": dashboard_id})

        if doc is None:
            return None

        doc.pop("_id", None)

        doc["dashboard_id"] = dashboard_id

        try:
            return Dashboard.from_dict(doc)
        except (KeyError, ValueError) as e:
            raise ValueError(f"Invalid dashboard data for ID {dashboard_id}: {e}") from e

    def get_by_user(self, user_id: str, collection_name: CollectionName | None = None) -> list[Dashboard]:
        """
        Get all dashboards for a user.

        :param user_id: User ID
        :type user_id: str
        :param collection_name: Filter by collection (None = all collections)
        :type collection_name: CollectionName or None

        :return: User's dashboards, with default first, then sorted by creation date (newest first)
        :rtype: list[Dashboard]
        """
        query = {"user_id": user_id}
        if collection_name:
            query["collection_name"] = collection_name

        cursor = self.collection.find(query).sort([("is_default", -1), ("created_at", -1)])

        dashboards = []
        for doc in cursor:
            doc.pop("_id", None)
            doc["dashboard_id"] = doc.get("dashboard_id")

            try:
                dashboard = Dashboard.from_dict(doc)
                dashboards.append(dashboard)
            except (KeyError, ValueError) as e:
                print(f"Warning: Skipping invalid dashboard: {e}")
                continue

        return dashboards

    def get_default(self, user_id: str, collection_name: CollectionName) -> Dashboard | None:
        """
        Get user's default dashboard for a collection.

        :param user_id: User ID
        :type user_id: str
        :param collection_name: Collection name
        :type collection_name: CollectionName

        :return: Default dashboard if exists, None otherwise
        :rtype: Dashboard or None
        """
        doc = self.collection.find_one({"user_id": user_id, "collection_name": collection_name, "is_default": True})

        if doc is None:
            return None

        doc.pop("_id", None)
        doc["dashboard_id"] = doc.get("dashboard_id")

        return Dashboard.from_dict(doc)

    def set_default(self, dashboard_id: str, user_id: str, collection_name: CollectionName) -> None:
        """
        Set a dashboard as user's default for a collection.

        :param dashboard_id: Dashboard to set as default
        :type dashboard_id: str
        :param user_id: User ID
        :type user_id: str
        :param collection_name: Collection name
        :type collection_name: CollectionName

        :raises ValueError: If dashboard not found or doesn't belong to user
        """
        dashboard = self.get_by_id(dashboard_id)
        if dashboard is None:
            raise ValueError(f"Dashboard {dashboard_id} not found")

        if dashboard.user_id != user_id:
            raise ValueError(f"Dashboard {dashboard_id} does not belong to user {user_id}")

        if dashboard.collection_name != collection_name:
            raise ValueError(
                f"Dashboard {dashboard_id} is for collection " f"{dashboard.collection_name}, not {collection_name}"
            )

        self.collection.update_many(
            {
                "user_id": user_id,
                "collection_name": collection_name,
                "is_default": True,
            },
            {"$set": {"is_default": False}},
        )
        self.collection.update_one({"dashboard_id": dashboard_id}, {"$set": {"is_default": True}})

    def delete(self, dashboard_id: str, user_id: str) -> bool:
        """
        Delete a dashboard.

        :param dashboard_id: Dashboard to delete
        :type dashboard_id: str
        :param user_id: User ID (must match dashboard owner)
        :type user_id: str

        :return: True if deleted, False if not found
        :rtype: bool

        :raises ValueError: If dashboard belongs to different user
        """
        # Verify dashboard belongs to user
        dashboard = self.get_by_id(dashboard_id)
        if dashboard is None:
            return False

        if dashboard.user_id != user_id:
            raise ValueError(f"Dashboard {dashboard_id} belongs to user {dashboard.user_id}, " f"not {user_id}")

        result = self.collection.delete_one({"dashboard_id": dashboard_id, "user_id": user_id})

        return result.deleted_count > 0

    def count_by_user(self, user_id: str, collection_name: CollectionName | None = None) -> int:
        """
        Count dashboards for a user.

        :param user_id: User ID
        :type user_id: str
        :param collection_name: Filter by collection (None = all collections)
        :type collection_name: CollectionName or None

        :return: Number of dashboards
        :rtype: int
        """
        query = {"user_id": user_id}
        if collection_name:
            query["collection_name"] = collection_name

        return self.collection.count_documents(query)
