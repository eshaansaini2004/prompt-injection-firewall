FROM python:3.11-slim

# sentence-transformers pulls in tokenizers (Rust ext) and numpy/scikit-learn
# which need build tools + libgomp at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Layer cache: install deps before copying source so a src-only change
# doesn't re-run pip install
COPY pyproject.toml ./
# Stub out the package so pip can resolve it without the real src present
RUN mkdir -p src/pif && touch src/pif/__init__.py \
    && pip install --no-cache-dir -e . \
    && rm -rf src/pif/__init__.py

# Now copy the real source
COPY src/ ./src/

# Pre-download the embedding model so first-request cold start is instant
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

RUN useradd --no-create-home --shell /bin/false pif \
    && chown -R pif:pif /app

USER pif

EXPOSE 8000

CMD ["uvicorn", "pif.proxy:app", "--host", "0.0.0.0", "--port", "8000"]
