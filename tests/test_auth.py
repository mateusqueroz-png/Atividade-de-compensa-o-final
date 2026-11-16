import re

import pytest

from app import app as flask_app

SENHA = "Senha1234"


@pytest.fixture
def client(tmp_path):
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False,
                            DATABASE=str(tmp_path / "teste.db"))
    return flask_app.test_client()


def cadastrar(c, email="ana@example.com", senha=SENHA, nome="Ana"):
    return c.post("/register", data={"name": nome, "email": email, "password": senha})


def entrar(c, email="ana@example.com", senha=SENHA):
    return c.post("/login", data={"email": email, "password": senha})


def test_cadastro_guarda_hash(client):
    assert cadastrar(client).status_code == 302
    import sqlite3
    row = sqlite3.connect(flask_app.config["DATABASE"]).execute("SELECT password_hash FROM users").fetchone()
    assert row[0] != SENHA and SENHA not in row[0]


def test_senha_fraca_e_email_invalido(client):
    assert cadastrar(client, senha="curta1").status_code == 200
    assert cadastrar(client, senha="somenteletras").status_code == 200
    assert cadastrar(client, email="invalido").status_code == 200


def test_email_duplicado(client):
    cadastrar(client)
    r = cadastrar(client, nome="Outra")
    assert r.status_code == 200 and "Não foi possível" in r.get_data(as_text=True)


def test_login_ok_e_falho(client):
    cadastrar(client)
    assert entrar(client, senha="errada123").status_code == 200
    assert entrar(client, email="x@example.com").status_code == 200
    assert entrar(client).status_code == 302
    assert client.get("/").status_code == 200


def test_sql_injection_no_login(client):
    cadastrar(client)
    r = entrar(client, email="' OR '1'='1' --", senha="qualquer")
    assert r.status_code == 200
    assert client.get("/").status_code == 302


def test_paginas_exigem_login(client):
    for url in ["/", "/tasks/new", "/tasks/1/edit"]:
        r = client.get(url)
        assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_logout_so_por_post(client):
    cadastrar(client); entrar(client)
    assert client.get("/logout").status_code == 405
    client.post("/logout")
    assert client.get("/").status_code == 302


def test_csrf_obrigatorio(client):
    flask_app.config["WTF_CSRF_ENABLED"] = True
    r = client.post("/register", data={"name": "Ana", "email": "a@example.com", "password": SENHA})
    assert r.status_code == 400
    html = client.get("/register").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    r = client.post("/register", data={"csrf_token": token, "name": "Ana",
                                       "email": "a@example.com", "password": SENHA})
    assert r.status_code == 302


def test_cabecalhos_e_cookie(client):
    cadastrar(client)
    r = entrar(client)
    assert "HttpOnly" in r.headers["Set-Cookie"] and "SameSite=Lax" in r.headers["Set-Cookie"]
    h = client.get("/login").headers
    assert "default-src 'self'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY" and h["X-Content-Type-Options"] == "nosniff"
