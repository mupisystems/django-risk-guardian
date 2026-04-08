# Contribuindo / Contributing

**[Português](#português) | [English](#english)**

---

## Português

### Como rodar o projeto localmente

```bash
git clone https://github.com/mupisystems/django-risk-guardian.git
cd django-risk-guardian
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install django django-redis pytest pytest-django fakeredis
pytest tests/ -v
```

### Convenções

- Código em inglês, docstrings/comments podem ser em português
- Formatação: sem linter obrigatório por enquanto, mas mantenha consistência com o código existente
- Testes são obrigatórios para qualquer novo analyzer ou funcionalidade
- Commits em inglês, imperativos e concisos (ex: "Add GeoIP analyzer")

### Fluxo de contribuição

1. Fork o repositório
2. Crie uma branch descritiva (`feature/geo-analyzer`, `fix/session-cache-bug`)
3. Implemente com testes
4. Abra um PR contra `main`
5. Aguarde review

### Criando um novo Analyzer

1. Crie um arquivo em `risk_guardian/analyzers/`
2. Herde de `BaseAnalyzer` e implemente `analyze(request, history) -> tuple[int, str | None]`
3. Adicione testes em `tests/test_analyzers.py`
4. Registre o dotted path no `DEFAULTS["ANALYZERS"]` em `conf.py`

---

## English

### Running the project locally

```bash
git clone https://github.com/mupisystems/django-risk-guardian.git
cd django-risk-guardian
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install django django-redis pytest pytest-django fakeredis
pytest tests/ -v
```

### Conventions

- Code in English, docstrings/comments may be in Portuguese
- Formatting: no mandatory linter yet, but stay consistent with existing code
- Tests are required for any new analyzer or feature
- Commits in English, imperative and concise (e.g., "Add GeoIP analyzer")

### Contribution flow

1. Fork the repository
2. Create a descriptive branch (`feature/geo-analyzer`, `fix/session-cache-bug`)
3. Implement with tests
4. Open a PR against `main`
5. Wait for review

### Creating a new Analyzer

1. Create a file in `risk_guardian/analyzers/`
2. Inherit from `BaseAnalyzer` and implement `analyze(request, history) -> tuple[int, str | None]`
3. Add tests in `tests/test_analyzers.py`
4. Register the dotted path in `DEFAULTS["ANALYZERS"]` in `conf.py`
