FROM python:3.13-slim

RUN apt-get update && \
    apt-get install -y nginx apache2-utils curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

COPY pyproject.toml uv.lock ./

RUN uv sync --frozen

COPY . ./

RUN mv nginx.conf /etc/nginx/conf.d/default.conf

RUN chmod +x entry.sh

EXPOSE 8080

CMD ["uv", "run", "./entry.sh"]

