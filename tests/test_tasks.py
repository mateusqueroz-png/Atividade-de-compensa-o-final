import sqlite3

from app import app as flask_app

from .test_auth import cadastrar, client, entrar  # noqa: F401


def nova(c, titulo="Estudar Flask", descricao="Cap. 3"):
    return c.post("/tasks/new", data={"title": titulo, "description": descricao})


def id_da_tarefa():
    return sqlite3.connect(flask_app.config["DATABASE"]).execute("SELECT id FROM tasks").fetchone()[0]


def test_criar_e_listar(client):
    cadastrar(client); entrar(client)
    assert nova(client).status_code == 302
    assert "Estudar Flask" in client.get("/").get_data(as_text=True)


def test_titulo_vazio_e_rejeitado(client):
    cadastrar(client); entrar(client)
    assert nova(client, titulo="   ").status_code == 200
    assert "Você ainda não tem tarefas" in client.get("/").get_data(as_text=True)


def test_editar_concluir_excluir(client):
    cadastrar(client); entrar(client); nova(client)
    tid = id_da_tarefa()
    client.post(f"/tasks/{tid}/edit", data={"title": "Novo", "description": ""})
    assert "Novo" in client.get("/").get_data(as_text=True)
    client.post(f"/tasks/{tid}/toggle")
    assert "Reabrir" in client.get("/").get_data(as_text=True)
    client.post(f"/tasks/{tid}/delete")
    assert "Você ainda não tem tarefas" in client.get("/").get_data(as_text=True)


def test_usuario_nao_acessa_tarefa_de_outro(client):
    cadastrar(client); entrar(client); nova(client, titulo="Segredo da Ana")
    tid = id_da_tarefa()
    client.post("/logout")

    cadastrar(client, email="bruno@example.com", nome="Bruno")
    entrar(client, email="bruno@example.com")
    assert "Segredo da Ana" not in client.get("/").get_data(as_text=True)
    assert client.get(f"/tasks/{tid}/edit").status_code == 404
    assert client.post(f"/tasks/{tid}/edit", data={"title": "Invadido"}).status_code == 404
    assert client.post(f"/tasks/{tid}/toggle").status_code == 404
    assert client.post(f"/tasks/{tid}/delete").status_code == 404
    titulo = sqlite3.connect(flask_app.config["DATABASE"]).execute("SELECT title FROM tasks").fetchone()[0]
    assert titulo == "Segredo da Ana"


def test_xss_e_escapado(client):
    cadastrar(client); entrar(client)
    nova(client, titulo="<script>alert(1)</script>", descricao="<img src=x onerror=alert(1)>")
    html = client.get("/").get_data(as_text=True)
    assert "<script>alert(1)" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html
