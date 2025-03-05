# Certificate Vector Search Demo

This is a single-file Python script that demonstrates how to process and search through certificate documents using vector embeddings. It’s not a full-blown project but rather a proof-of-concept for semantic search over certificate datasets. It’s designed to be simple and accurate, though not highly scalable out of the box.

---

## What It Does

1. **Processes Certificate Documents**:
   - Takes a dataset of certificates (loaded from a JSON file).
   - Extracts text from associated `.txt` files (e.g., reports, security targets, certificates).
   - Splits the text into smaller, overlapping chunks (512 tokens max, with 128 tokens of overlap) to handle large documents.

2. **Generates Embeddings**:
   - Uses the `sentence-transformers/all-MiniLM-L6-v2` model to convert each text chunk into a vector embedding. It's a small model that can be run on the CPU.
   - Stores these embeddings in a SQLite database with vector support (thanks to `sqlite-vec`).

3. **Makes It Searchable**:
   - You can query the database with a text string, and it’ll find the most semantically similar chunks of text from the certificates. The query is embedded with the aforementioned `sentence-transformers` model.
   - Results include metadata (like certificate name, source type, etc.) and the actual text of the chunk.

4. **Provides a Web Interface**:
   - A simple HTTP server lets you interact with the system via a browser.
   - Submit a query, and it’ll show you the top results with snippets of the most relevant text.
---

## How It Works

### Dataset Processing
- The dataset is validated to ensure it contains the required files (`dataset.json` and `.txt` files).
- Text is extracted from the `.txt` files, split into chunks, and converted into embeddings.

### Database Setup
The SQLite database has three main tables:
- **`cert_chunks`**: Stores the vector embeddings, along with metadata like the certificate digest and chunk index.
- **`metadata`**: Stores certificate-level info (name, manufacturer, validity dates, etc.).
- **`chunk_texts`**: Stores the actual text of each chunk for easy retrieval.

The database is initialized with vector support using the `sqlite-vec` extension, which enables similarity searches.

### Querying
- When you submit a query, the system:
  1. Converts the query text into an embedding.
  2. Searches the database for chunks with the closest embeddings.
  3. Groups chunks by unique document (digest x document type: report, security target) combination.
  4. Ranks results using a weighted score (combining the closest match and average similarity).
  5. Returns the top `k` results, including metadata and the text of the most relevant chunk.

### Web Interface
- A basic HTTP server runs locally, serving a simple HTML page where you can enter queries and see results.
- The user query is embedded on the back-end and a similarity search is performed.
- Results are displayed with the certificate name, source type, similarity score, and a snippet of the text.

---

## Scalability Notes

This demo uses [brute-force](https://github.com/asg017/sqlite-vec/issues/172#issuecomment-2608754427) linear search for simplicity and accuracy. While this works fine for small to medium datasets, it’s not scalable for large datasets. For better performance, you could integrate:

- **Approximate Nearest Neighbor (ANN) Search**: Plugins supporting approaches like [FAISS](https://github.com/maylad31/vector_sqlite) or [HNSW](https://github.com/nmslib/hnswlib) can speed up retrieval for large datasets, at the cost of some accuracy.
- **Vectorlite**: A lightweight SQLite [extension](https://github.com/1yefuwang1/vectorlite) for fast vector search, seems most reasonable as an upgrade.

---

## Mixed Search
In the future, it might be desirable to combine semantic search (vector embeddings) with keyword-based search (BM25 or TF-IDF) for hybrid retrieval.


## How to Use It

1. **Install Dependencies**:
   ```bash
   pip install sec_certs sentence-transformers nltk sqlite-vec
   ```

2. **Run the Script**:
   ```bash
   python vector_search.py --data-path /path/to/dataset --db-path /path/to/database.sqlite --force-rebuild --port 8080
   ```
   - `--data-path`: Path to the dataset directory (should contain `dataset.json` and the `certs` folder).
   - `--db-path`: Path to the SQLite database file.
   - `--force-rebuild`: Rebuild the database from scratch (optional).
   - `--port`: Port to run the HTTP server on (default is 8000).

3. **Search**:
   - Open your browser and go to `http://localhost:8000`.
   - Enter a query, and see the results!

---


## Code Overview

The script is a single Python file with the following key components:
- **`CertProcessor`**: Handles dataset processing, embedding generation, and database storage.
- **`query_similar_chunks`**: Queries the database for similar chunks and returns results with metadata.
- **`Server`**: A simple HTTP server that serves the web interface and handles search queries.

---

## Dependencies

- `sentence-transformers`: For generating text embeddings.
- `nltk`: For tokenizing text into words.
- `sqlite-vec`: For enabling vector operations in SQLite.
- `sec_certs`: For loading and processing the certificate dataset.
