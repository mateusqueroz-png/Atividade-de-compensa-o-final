# Minhas Tarefas (versão simples)

Sistema web onde cada usuário cria conta, faz login e gerencia **as próprias tarefas**.

- Python + Flask · SQLite (módulo `sqlite3`) · HTML com Jinja2
- Código principal em um único arquivo: `app.py`

## Como rodar

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # Windows: copy .env.example .env
# gere uma chave e cole em SECRET_KEY dentro do .env:
python -c "import secrets; print(secrets.token_hex(32))"
python app.py                      # abre em http://127.0.0.1:5000
```

O banco é criado sozinho em `instance/app.db`. Testes: `python -m pytest -q`

## Estrutura

```
app.py          # rotas, banco e segurança
schema.sql      # tabelas users e tasks
templates/      # páginas HTML
static/         # CSS
tests/          # testes automatizados
```

## Segurança aplicada

| Proteção | Como |
|---|---|
| Senha | Hash com Werkzeug (`generate_password_hash`), nunca em texto puro; mínimo de 8 caracteres com letras e números |
| SQL Injection | Todas as consultas usam parâmetros (`?`) |
| XSS | Jinja2 escapa tudo + cabeçalho CSP sem scripts inline |
| CSRF | Flask-WTF: token em todos os formulários POST |
| Acesso aos dados | Toda consulta de tarefa filtra por `user_id` da sessão (tarefa alheia retorna 404) |
| Sessão | Cookie `HttpOnly`, `SameSite=Lax`, expira em 30 min, `session.clear()` no login |
| Login | Mensagem de erro única (não revela se o e-mail existe); logout só por POST |
| Segredos | `SECRET_KEY` no `.env` (fora do Git) |
| Cabeçalhos | CSP, `X-Frame-Options`, `nosniff`, `Cache-Control: no-store` |
| Erros | Páginas genéricas, sem detalhes internos |

Ao publicar em um servidor com HTTPS, coloque `HTTPS=1` no `.env` para o cookie ser `Secure`.
