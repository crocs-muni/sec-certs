import os

from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError

from .dashboard import Dashboard
from .types.common import CollectionName


class DashboardRepository:
    """Repository for Dashboard persistence in MongoDB."""

    def __init__(self, db: Database, collection_name: str = "dashboards"):
        self.collection: Collection = db[collection_name]
        # Skip index creation during testing (MongoDB not available yet)
        if not os.environ.get("TESTING"):
            self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        self.collection.create_index("user_id")
        self.collection.create_index(
            [("user_id", 1), ("collection_name", 1), ("is_default", 1)],
            unique=True,
            partialFilterExpression={"is_default": True},
        )
        self.collection.create_index([("created_at", -1)])

    def get_names_by_user(
        self,
        user_id: str,
        collection_name: CollectionName | None = None,
    ) -> list[dict[str, str]]:
        """
        Get dashboard names and IDs for dropdown population (minimal query).

        :param user_id: User ID
        :param collection_name: Filter by collection (None = all)
        :return: List {dashboard_id, name, is_default} dicts
        """
        query: dict = {"user_id": user_id}
        if collection_name:
            query["collection_name"] = collection_name.value

        cursor = self.collection.find(
            query,
            {"dashboard_id": 1, "name": 1, "is_default": 1, "_id": 0},
        ).sort([("is_default", -1), ("created_at", -1)])

        return [
            {
                "dashboard_id": doc["dashboard_id"],
                "name": doc["name"],
                "is_default": doc.get("is_default", False),
            }
            for doc in cursor
        ]

    def save(self, dashboard: Dashboard) -> str:
        """
        Save or update a dashboard in the database.

        :param dashboard: Dashboard to save
        :return: The dashboard ID
        """
        serialized_dashboard = dashboard.to_dict()
        dashboard_id = serialized_dashboard.pop("dashboard_id")

        try:
            if dashboard.is_default:
                self.collection.update_many(
                    {
                        "user_id": dashboard.user_id,
                        "collection_name": dashboard.collection_name.value,
                        "is_default": True,
                        "dashboard_id": {"$ne": dashboard_id},
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
        doc = self.collection.find_one({"dashboard_id": dashboard_id})
        if doc is None:
            return None

        doc.pop("_id", None)

        try:
            return Dashboard.from_dict(doc)
        except (KeyError, ValueError) as e:
            raise ValueError(f"Invalid dashboard data for ID {dashboard_id}: {e}") from e

    def get_by_user(self, user_id: str, collection_name: CollectionName | None = None) -> list[Dashboard]:
        query: dict = {"user_id": user_id}
        if collection_name:
            query["collection_name"] = collection_name.value

        cursor = self.collection.find(query).sort([("is_default", -1), ("created_at", -1)])

        dashboards = []
        for doc in cursor:
            doc.pop("_id", None)
            try:
                dashboard = Dashboard.from_dict(doc)
                dashboards.append(dashboard)
            except (KeyError, ValueError):
                continue

        return dashboards

    def get_default(self, user_id: str, collection_name: CollectionName) -> Dashboard | None:
        doc = self.collection.find_one(
            {
                "user_id": user_id,
                "collection_name": collection_name.value,
                "is_default": True,
            }
        )

        if doc is None:
            return None

        doc.pop("_id", None)
        doc["dashboard_id"] = doc.get("dashboard_id")
        return Dashboard.from_dict(doc)

    def set_default(self, dashboard_id: str, user_id: str, collection_name: CollectionName) -> None:
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
            {"user_id": user_id, "collection_name": collection_name.value, "is_default": True},
            {"$set": {"is_default": False}},
        )
        self.collection.update_one({"dashboard_id": dashboard_id}, {"$set": {"is_default": True}})

    def delete(self, dashboard_id: str, user_id: str) -> bool:
        dashboard = self.get_by_id(dashboard_id)
        if dashboard is None:
            return False

        if dashboard.user_id != user_id:
            raise ValueError(f"Dashboard {dashboard_id} belongs to user {dashboard.user_id}, not {user_id}")

        result = self.collection.delete_one({"dashboard_id": dashboard_id, "user_id": user_id})
        return result.deleted_count > 0

    def count_by_user(self, user_id: str, collection_name: CollectionName | None = None) -> int:
        query: dict = {"user_id": user_id}
        if collection_name:
            query["collection_name"] = collection_name.value

        return self.collection.count_documents(query)
