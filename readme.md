# CheckTarget 🔎🛡️

Ferramenta de **perfilamento técnico, enumeração e coleta inicial de evidências** para **ambientes de laboratório autorizados**, com foco em estudo de **pentest**, **perícia forense**, **DFIR** e automação de tarefas repetitivas.

> ⚠️ **Aviso importante**  
> Este projeto foi desenvolvido **exclusivamente para fins educacionais, estudo e validação técnica em ambiente controlado e autorizado**.  
> **Não utilize em redes, aplicações, hosts ou dispositivos de terceiros sem autorização formal.**  
> O uso inadequado pode gerar consequências **legais, éticas e operacionais**.

---

## Visão geral

Em cenários de análise técnica, resposta a incidentes, perícia digital e reconhecimento em laboratório, **cada segundo conta**.

A proposta deste projeto é automatizar tarefas iniciais e repetitivas, como:

- identificação de **portas abertas**
- enumeração de **rotas e endpoints**
- descoberta de **arquivos potencialmente expostos**
- análise de **headers, cookies, CORS e métodos HTTP**
- fingerprint leve de **frameworks e tecnologias**
- coleta de **evidências HTTP**
- geração de relatórios em **CSV, JSON e HTML**
- comparação entre varreduras **antes e depois**

Isso ajuda a reduzir tempo operacional e aumentar a visibilidade do ambiente analisado.

---

## O que este projeto faz

### Perfilador principal

O script principal realiza:

- **varredura de portas** mais comuns
- tentativa de leitura de **banner de serviço**
- identificação de tecnologias web por **fingerprint leve**
- análise de:
  - headers de segurança
  - cookies
  - CORS
  - métodos HTTP sensíveis
- enumeração de:
  - caminhos comuns
  - arquivos expostos por extensão
  - endpoints relevantes
- captura de **evidências HTTP**
- geração de relatórios em:
  - `CSV`
  - `JSON`
  - `HTML`
- comparação entre relatórios JSON

### Lab Flask vulnerável

O lab foi criado para estudo local e permite simular um ambiente com **falhas propositais**, como:

- login em HTTP
- headers ausentes
- rota administrativa mal protegida
- `.env` exposto
- endpoint de debug
- OpenAPI exposta
- API retornando dados demais
- upload sem validação adequada
- cookies fracos
- comentários e indicadores sensíveis no HTML

---

## Casos de uso

### Pentest em laboratório

Ajuda na fase de:

- reconhecimento
- enumeração
- perfilamento do alvo
- descoberta de superfícies expostas
- organização de achados para validação manual posterior

### Perícia forense / DFIR

Ajuda em atividades como:

- levantamento inicial do ambiente
- coleta rápida de evidências HTTP
- documentação técnica de exposição
- triagem inicial de ativos e serviços
- criação de base para investigação mais aprofundada

### Segurança ofensiva e defensiva para estudo

Permite observar, de forma didática:

- o que está exposto
- o que está mal configurado
- o que deveria estar restrito
- o que precisa ser corrigido antes de produção

---

## Estrutura do projeto

```text
.
├── checktarget.py
├── config.yaml
├── lab.py
├── evidencias/
├── perfilador_relatorio.csv
├── perfilador_relatorio.json
└── perfilador_relatorio.html
```

### Arquivos

- `checktarget.py`  
  Script principal do perfilador.

- `config.yaml`  
  Arquivo de configuração com URL alvo, host, portas, caminhos comuns, extensões e parâmetros do fluxo de login.

- `lab.py`  
  Aplicação Flask vulnerável de propósito para testes locais.

- `evidencias/`  
  Pasta gerada automaticamente com snippets de respostas HTTP coletadas durante a execução.

- `perfilador_relatorio.csv`  
  Relatório estruturado em formato tabular.

- `perfilador_relatorio.json`  
  Relatório estruturado em JSON, útil para comparação e integração.

- `perfilador_relatorio.html`  
  Relatório visual em HTML com resumo executivo, tecnologias, endpoints e achados.

---

## Requisitos

- Python **3.10+** recomendado
- Ambiente virtual opcional, mas recomendado

### Dependências

```bash
pip install flask requests beautifulsoup4 pyyaml
```

---

## Instalação

### 1. Clone o repositório

```bash
git clone <SEU-REPOSITORIO>
cd <PASTA-DO-PROJETO>
```

### 2. Crie e ative um ambiente virtual

#### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

#### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instale as dependências

```bash
pip install flask requests beautifulsoup4 pyyaml
```

---

## Configuração

Edite o arquivo `config.yaml`.

### Exemplo mínimo

```yaml
target_url: "http://127.0.0.1:5000"
target_host: "127.0.0.1"

timeouts:
  http: 5
  socket: 1

outputs:
  csv: "perfilador_relatorio.csv"
  html: "perfilador_relatorio.html"
  json: "perfilador_relatorio.json"
  evidence_dir: "evidencias"
```

### Diferença entre `target_url` e `target_host`

- **`target_url`**: endereço base da aplicação web
- **`target_host`**: host/IP usado para varredura de portas

#### Exemplo

Se a aplicação estiver em:

```text
http://127.0.0.1:5000/login
```

Então use:

```yaml
target_url: "http://127.0.0.1:5000"
target_host: "127.0.0.1"
```

---

## Executando o laboratório Flask

O lab vulnerável foi pensado para testes **locais**.

### Inicie o lab

```bash
python lab.py
```

Depois acesse no navegador:

```text
http://127.0.0.1:5000
```

### Credenciais do lab

- **usuário:** `admin`
- **senha:** `admin123`

ou

- **usuário:** `filipe`
- **senha:** `senha123`

---

## Executando o perfilador

Com o lab já rodando, execute em outro terminal:

```bash
python checktarget.py
```

### Saídas esperadas

- `perfilador_relatorio.csv`
- `perfilador_relatorio.json`
- `perfilador_relatorio.html`
- pasta `evidencias/`

---

## Comparando dois relatórios

O projeto também permite comparar dois arquivos JSON gerados em momentos diferentes.

### Exemplo

```bash
python checktarget.py compare relatorio_antigo.json relatorio_novo.json
```

Isso ajuda a visualizar:

- achados removidos
- novos achados
- impacto de correções aplicadas

---

## O que o perfilador consegue identificar

### Rede / serviços

- portas abertas
- serviços prováveis
- banners simples
- superfície exposta

### Web / aplicação

- headers ausentes
- banner de servidor exposto
- cookies inseguros
- CORS permissivo
- métodos HTTP sensíveis
- formulários com possíveis sinais de fragilidade
- caminhos e arquivos expostos
- documentação de API exposta
- endpoints administrativos

### Tecnologias

Fingerprint leve de componentes como:

- Flask / Werkzeug
- Django
- Laravel
- Express
- ASP.NET
- Spring
- Rails
- React
- Vue
- Angular
- Bootstrap
- Swagger / OpenAPI

### Evidências

- snippets de resposta HTTP
- endpoints acessíveis
- recursos expostos
- base documental para análise técnica

---

## Como isso ajuda na perícia forense

Em atividades forenses e de DFIR, o projeto pode ajudar a:

- acelerar o **levantamento inicial do ambiente**
- padronizar a **coleta de evidências HTTP**
- apoiar a documentação técnica de ativos e exposições
- organizar indícios que exigem análise manual posterior
- reduzir o tempo gasto em tarefas repetitivas

Em resumo, ele funciona como uma etapa de **triagem e visibilidade inicial**.

---

## Como isso ajuda no pentest

No contexto de pentest em ambiente controlado, o projeto ajuda na fase de:

- reconhecimento
- enumeração
- descoberta de superfície de ataque
- priorização de validações manuais
- documentação de achados

Ele **não substitui a análise do profissional**, mas acelera o processo e melhora a organização da etapa inicial.

---

## Limitações importantes

Este projeto **não foi criado para exploração ofensiva**.

Ele **não realiza**:

- brute force
- exploração automatizada de falhas
- execução de payloads
- bypass de autenticação
- extração de credenciais reais
- abuso de terceiros

A proposta é **auditoria técnica, estudo e análise controlada**.

---

## Segurança e ética

> ⚠️ Reforçando: este projeto deve ser usado **somente em laboratório próprio, ambiente autorizado ou fins educacionais controlados**.

Segurança não é apenas ferramenta. É também **responsabilidade, autorização e contexto**.

---

## Roadmap

Possíveis evoluções futuras:

- modo **multi-alvo**
- score de risco por ativo
- saída colorida no terminal
- baseline de hardening
- comparativo visual entre relatórios
- suporte a configuração por perfis
- melhoria do fingerprint de tecnologias

---

## Exemplo de execução

### Terminal 1

```bash
python lab.py
```

### Terminal 2

```bash
python checktarget.py
```

---

## Exemplo de posturas identificadas

O relatório pode indicar cenários como:

- **controlado**
- **moderado**
- **elevado**

A classificação considera a quantidade e a severidade dos achados encontrados.

---

## Contribuição

Contribuições são bem-vindas para:

- melhoria de documentação
- novas checagens seguras
- ajustes no parser de evidências
- refino de relatórios
- melhorias de qualidade do código

---

## Licença

Defina aqui a licença do projeto, por exemplo:

```text
MIT License
```

---

## Autor

Projeto desenvolvido para estudo de:

- automação em cibersegurança
- enumeração técnica
- perícia forense
- pentest em ambiente controlado
- documentação e coleta inicial de evidências

Se publicar no GitHub, vale muito adicionar também:

- prints dos relatórios
- GIF curto de execução
- comparação antes/depois
- seção de aprendizado

---

## Disclaimer final

**Este projeto é voltado para estudo e ambiente controlado.**  
**Não utilize contra terceiros, infraestruturas públicas ou sistemas sem autorização expressa.**

