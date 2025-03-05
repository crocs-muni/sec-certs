import argparse
import sqlite3
import struct
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import nltk
import sqlite_vec
from nltk.tokenize import word_tokenize
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

from sec_certs.dataset import CCDataset
from sec_certs.sample import CCCertificate

# initialize NLP resources - one-time downloads
nltk.download("punkt")
nltk.download("punkt_tab")

TOKEN_LIMIT = 512
OVERLAP = 128
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def serialize_f32(vector: list[float]) -> bytes:
    """Serialize float list to bytes for sqlite_vec"""
    return struct.pack(f"{len(vector)}f", *vector)


class CertProcessor:
    def __init__(self, model=None, fresh_db=False):
        if model is not None:
            self.model = model
        else:
            self.model = SentenceTransformer(MODEL_NAME)
        self.db = self.init_db(fresh_db)
        self.cursor = self.db.cursor()

    def init_db(self, fresh_db) -> sqlite3.Connection:
        """Initialize database with vector extension"""
        conn = sqlite3.connect(DB_PATH)
        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)

        if fresh_db is True:
            conn.execute("DROP TABLE IF EXISTS cert_chunks;")
            conn.execute("DROP TABLE IF EXISTS metadata;")
            conn.execute("DROP TABLE IF EXISTS chunk_texts;")

            conn.execute("""
                CREATE VIRTUAL TABLE cert_chunks USING vec0(
                    embedding float[384],
                    dgst TEXT,
                    chunk_index INTEGER,
                    source_type TEXT,
                )
            """)
            conn.execute("""
                CREATE TABLE metadata (
                    dgst TEXT PRIMARY KEY,
                    name TEXT,
                    category TEXT,
                    manufacturer TEXT,
                    security_level TEXT,
                    valid_from TEXT,
                    valid_to TEXT,
                    report_link TEXT,
                    st_link TEXT,
                    cert_link TEXT,
                    manufacturer_web TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE chunk_texts (
                    dgst TEXT,
                    source_type TEXT,
                    chunk_index INTEGER,
                    text TEXT,
                    PRIMARY KEY (dgst, source_type, chunk_index)
                )
            """)

            # create indices for metadata
            conn.execute("CREATE INDEX idx_chunk_texts_dgst ON chunk_texts(dgst);")
            conn.execute("CREATE INDEX idx_chunk_texts_source ON chunk_texts(source_type);")

        return conn

    def store_metadata(self, meta: dict) -> None:
        """Store certificate metadata in the metadata table"""
        params = {
            "dgst": meta["dgst"],
            "name": meta.get("name", "Unknown"),
            "category": meta.get("category", "unknown"),
            "manufacturer": meta.get("manufacturer", "Unknown"),
            "security_level": ",".join(meta.get("security_level", [])),
            "valid_from": meta["not_valid_before"].isoformat(),
            "valid_to": meta["not_valid_after"].isoformat(),
            "report_link": meta.get("report_link", ""),
            "st_link": meta.get("st_link", ""),
            "cert_link": meta.get("cert_link", ""),
            "manufacturer_web": meta.get("manufacturer_web", ""),
        }
        self.cursor.execute(
            """
            INSERT INTO metadata
            (dgst, name, category, manufacturer, security_level,
             valid_from, valid_to, report_link, st_link, cert_link, manufacturer_web)
            VALUES (:dgst, :name, :category, :manufacturer, :security_level,
                    :valid_from, :valid_to, :report_link, :st_link, :cert_link, :manufacturer_web)
        """,
            params,
        )

    def chunk_text(self, text: str) -> list[str]:
        """Split text into overlapping chunks"""
        words = word_tokenize(text)
        return [" ".join(words[i : i + TOKEN_LIMIT]) for i in range(0, len(words), TOKEN_LIMIT - OVERLAP)]

    def process_cert(self, cert: CCCertificate) -> None:
        """Process a single certificate with all its documents"""
        meta = cert.to_dict()
        file_paths = {
            "report": cert.state.report._txt_path,
            "targets": cert.state.st._txt_path,
            "cert": cert.state.cert._txt_path,
        }

        for doc_type, path in file_paths.items():
            if path is None or not path.exists():
                continue

            with path.open(encoding="utf-8") as f:
                text = f.read()

            chunks = self.chunk_text(text)
            self.store_chunks(chunks, meta, doc_type)

    def store_chunks(self, chunks: list[str], meta: dict, doc_type: str) -> None:
        """Store chunks with metadata in database"""
        for idx, chunk in enumerate(tqdm(chunks, desc=f"Chunking {doc_type}", leave=False)):
            # generate embedding
            embedding = self.model.encode(chunk).flatten().tolist()

            # insert into cert_chunks table
            self.cursor.execute(
                """
                INSERT INTO cert_chunks
                (embedding, dgst, chunk_index, source_type)
                VALUES (?, ?, ?, ?)
            """,
                [serialize_f32(embedding), meta["dgst"], idx, doc_type],
            )

            self.cursor.execute(
                """
                INSERT INTO chunk_texts
                (dgst, source_type, chunk_index, text)
                VALUES (?, ?, ?, ?)
            """,
                [meta["dgst"], doc_type, idx, chunk],
            )

        # store metadata if not already present
        self.cursor.execute("SELECT dgst FROM metadata WHERE dgst = ?", [meta["dgst"]])
        if not self.cursor.fetchone():
            self.store_metadata(meta)

    def process_all(self, dataset) -> None:
        """Process entire dataset"""
        for cert in tqdm(dataset, desc="Processing certificates", unit="cert"):
            self.process_cert(cert)
        self.db.commit()

    def close(self) -> None:
        """Close the database connection"""
        self.cursor.close()
        self.db.close()


def query_similar_chunks(
    query_text: str, processor: CertProcessor, k: int = 5
) -> list[tuple[str, str, str, str, str, str]]:
    """
    Query the database for similar chunks and include metadata.

    Args:
        query_embedding: The embedding of the query text.
        processor: An instance of CertProcessor.
        k: The number of results to return.

    Returns:
        A list of tuples containing (dgst, name, chunk_index, source_type, distance).
    """
    query_embedding = processor.model.encode(query_text).flatten().tolist()
    serialized_query = serialize_f32(query_embedding)

    # fetch similar chunks and join with metadata
    query = """
        SELECT
        m.dgst,
        m.name,
        c.source_type,
        0.7 * MIN(c.distance) + 0.3 * AVG(c.distance) AS weighted_score,
        first_value(c.chunk_index) OVER (
            PARTITION BY m.dgst, c.source_type
            ORDER BY c.distance ASC
        ) AS best_chunk_index
        FROM cert_chunks c
        JOIN metadata m ON c.dgst = m.dgst
        WHERE c.embedding MATCH ? AND k=2000
        GROUP BY
        m.dgst, c.source_type
        ORDER BY
        weighted_score ASC
        LIMIT ?
        """

    doc_results = processor.db.execute(query, [serialized_query, k]).fetchall()

    # fetch the text for each best chunk
    results_with_text = []
    for dgst, name, source_type, weighted_score, best_chunk_idx in doc_results:
        # query to get the text chunk
        text_query = """
            SELECT text
            FROM chunk_texts
            WHERE dgst = ? AND source_type = ? AND chunk_index = ?
        """
        text_result = processor.db.execute(text_query, [dgst, source_type, best_chunk_idx]).fetchone()
        chunk_text = text_result[0] if text_result else "Text not found"

        # add text chunk to result
        results_with_text.append((dgst, name, source_type, weighted_score, best_chunk_idx, chunk_text))

    return results_with_text


source_map = {"targets": "Security target", "report": "Certification report", "cert": "Certificate"}


class Server(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()

        # parse query
        query = ""
        results = []
        if "?" in self.path:
            query = urllib.parse.parse_qs(self.path.split("?")[1]).get("q", [""])[0]
            if query:
                results = query_similar_chunks(query, processor, k=5)

        # Build response
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Cert Search</title>
            <style>
                body {{ font-family: sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }}
                .result {{ border: 1px solid #ddd; margin: 15px 0; padding: 15px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Certificate Vector Search</h1>
            <form method="get">
                <input type="text" name="q" placeholder="Search query..." value="{query}">
                <input type="submit" value="Search">
            </form>
        """

        if results:
            html += "<h2>Results</h2>"
            for dgst, name, source_type, score, chunk_idx, text in results:
                html += f"""
                <div class="result">
                    <h3>{name}</h3>
                    <p>Source: {source_map.get(source_type, "Unknown")} | Score: {score:.4f}</p>
                    <p>{text[:500]}...</p>
                </div>
                """

        html += "</body></html>"
        self.wfile.write(html.encode())


def check_dataset_path(path_dset: Path) -> bool:
    """Verify that the dataset path exists and contains dataset.json."""
    if not path_dset.exists():
        print(f"Error: Dataset path '{path_dset}' does not exist")
        sys.exit(1)

    if not (path_dset / "dataset.json").exists():
        print(f"Error: dataset.json not found in '{path_dset}'")
        sys.exit(1)

    return True


def check_certificate_count(dset: CCDataset) -> int:
    """Check and report the number of certificates in the dataset."""
    cert_count = len(list(dset.certs))
    print(f"Dataset contains {cert_count} certificates")
    if cert_count == 0:
        print("Error: Dataset is empty")
        sys.exit(1)

    return cert_count


def check_txt_files(path_dset: Path) -> int:
    """Verify that text files exist in the expected directories."""
    txt_paths = [path_dset / "certs/certificates/txt", path_dset / "certs/reports/txt", path_dset / "certs/targets/txt"]

    txt_counts = []
    for path in txt_paths:
        if path.exists():
            count = len(list(path.glob("*.txt")))
            txt_counts.append(count)
            print(f"Found {count} .txt files in {path}")
        else:
            print(f"Warning: Path {path} does not exist")
            txt_counts.append(0)

    total = sum(txt_counts)
    if total == 0:
        print("Error: No .txt files found in any of the expected directories")
        sys.exit(1)

    return total


def manage_database(db_path: Path, model: SentenceTransformer, force_rebuild: bool, dset: CCDataset) -> bool:
    """Create or rebuild the database if needed."""
    if force_rebuild or not db_path.exists():
        print(f"{'Rebuilding' if force_rebuild else 'Creating'} database at {db_path}")
        if db_path.exists() and force_rebuild:
            db_path.unlink()

        processor = CertProcessor(model, fresh_db=True)
        processor.process_all(dset)
        processor.close()
        print("Database initialization complete.")
        return True
    return False


# pip install sec_certs sentence-transformers nltk sqlite-vec
# Usage example: python vector_search.py --data-path ../../cc_data_gemini --db-path vector_db.sqlite --force-rebuild --port 8080
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Certificate Vector Search")
    parser.add_argument("--data-path", type=str, default="../../cc_data_gemini", help="Path to the dataset directory")
    parser.add_argument("--db-path", type=str, default="vector_db.sqlite", help="Path to the SQLite database file")
    parser.add_argument("--force-rebuild", action="store_true", help="Force database rebuild even if it exists")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server on")
    args = parser.parse_args()

    path_dset = Path(args.data_path)
    DB_PATH = Path(args.db_path)

    check_dataset_path(path_dset)

    dset = CCDataset.from_json(path_dset / "dataset.json")

    cert_count = check_certificate_count(dset)
    txt_count = check_txt_files(path_dset)

    model = SentenceTransformer(MODEL_NAME)

    db_rebuilt = manage_database(DB_PATH, model, args.force_rebuild, dset)

    processor = CertProcessor(model, fresh_db=False)

    server = HTTPServer(("localhost", 8000), Server)
    print("Server started at http://localhost:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        processor.close()
        print("Server stopped.")
