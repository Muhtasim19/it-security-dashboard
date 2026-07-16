# IT Security Dashboard

A lightweight security monitoring dashboard built as part of an **IT Operations Suite**. It combines asset, ticket, vulnerability, scan, remediation, alert, and risk data into one web interface.

The project was developed by **Muhtasim** and **Sabirul** as a continuation of the following completed projects:

- IT Helpdesk and Asset Management System
- Network Vulnerability Scanner

## Project Status

**Project 3: Completed locally and ready for final merge/deployment**

Current capabilities include:

- Responsive security dashboard
- Asset totals
- Open helpdesk ticket totals
- Open remediation ticket totals
- Vulnerabilities grouped by severity
- Most vulnerable asset ranking
- Organization-wide security risk score
- Latest vulnerability scans
- Recent security alerts
- JSON API endpoints
- Automated unit and integration tests

## Screens and Metrics

The dashboard displays:

- Total managed assets
- Open helpdesk tickets
- Total open vulnerabilities
- Overall risk score from 0 to 100
- Critical, high, medium, and low vulnerability counts
- Most vulnerable assets
- Latest vulnerability scans
- Recent security alerts
- Risk factors such as:
  - Severity points
  - Known-exploited vulnerability bonus
  - Internet exposure bonus
  - Critical asset bonus
  - Overdue remediation bonus

## Technology Stack

- **Backend:** Python and Flask
- **Frontend:** HTML, CSS, JavaScript, and Jinja templates
- **Data source:** JSON sample data
- **Testing:** Python `unittest`
- **Version control:** Git and GitHub

## Project Structure

```text
it-security-dashboard/
├── dashboard/
│   ├── __init__.py
│   ├── alerts.py
│   ├── asset_metrics.py
│   ├── dashboard.py
│   ├── risk_score.py
│   ├── ticket_metrics.py
│   └── vulnerability_metrics.py
├── data/
│   └── sample_data.json
├── database/
│   ├── __init__.py
│   ├── db.py
│   └── schema.sql
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── dashboard.js
├── templates/
│   └── dashboard.html
├── tests/
│   ├── test_dashboard_integration.py
│   ├── test_metrics.py
│   └── test_risk_score.py
├── .gitignore
├── LICENSE
├── main.py
├── README.md
└── requirements.txt
```

## Team Responsibilities

### Muhtasim

- Dashboard layout
- Vulnerability severity metrics
- Most vulnerable asset ranking
- Overall risk score
- Final integration and testing

### Sabirul

- Sample data
- Total asset metric
- Helpdesk ticket metric
- Remediation ticket metric
- Latest scan metric
- Security alert data and helpers

## Git Workflow

The project uses the following branch structure:

```text
main
└── develop
    ├── feature/dashboard-layout
    ├── feature/vulnerability-metrics
    ├── feature/risk-score
    ├── feature/sample-data
    ├── feature/asset-metrics
    ├── feature/ticket-metrics
    ├── feature/security-alerts
    └── integration/dashboard-complete
```

Feature branches are merged into `develop`. After integration and testing, `develop` is merged into `main`.

## Local Installation

### 1. Clone the repository

```bash
git clone https://github.com/Muhtasim19/it-security-dashboard.git
cd it-security-dashboard
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Start the application

```bash
python main.py
```

Open the dashboard at:

```text
http://127.0.0.1:5000
```

## API Endpoints

### Health check

```text
GET /health
```

Example response:

```json
{
  "service": "it-security-dashboard",
  "status": "healthy"
}
```

### Dashboard summary

```text
GET /api/dashboard/summary
```

Returns the integrated summary, latest scans, recent alerts, and update time.

### Vulnerability metrics

```text
GET /api/vulnerabilities/metrics
```

Returns:

- Total open vulnerabilities
- Severity counts
- Most vulnerable assets

### Risk score

```text
GET /api/risk-score
```

Returns:

- Score from 0 to 100
- Risk level
- Risk description
- Open vulnerability count
- Individual risk factors
- Calculation time

## Risk-Score Logic

The organizational risk score is calculated from open vulnerabilities and additional exposure factors.

### Severity points

| Severity | Points |
|---|---:|
| Critical | 25 |
| High | 15 |
| Medium | 7 |
| Low | 2 |

### Additional factors

| Factor | Bonus |
|---|---:|
| Known exploited | 10 |
| Internet exposed | 5 |
| Critical asset | Up to 5 |
| Overdue remediation | 5 |

The final score is capped at `100`.

### Risk levels

| Score | Level |
|---|---|
| No vulnerabilities | No data |
| 1–19 | Low |
| 20–39 | Moderate |
| 40–69 | High |
| 70–100 | Critical |

## Testing

Run all tests:

```bash
python -m unittest discover -s tests -v
```

The current test suite covers:

- Vulnerability extraction
- Closed vulnerability filtering
- Severity normalization
- Severity totals
- Most vulnerable asset ranking
- Risk-score calculation
- Additional risk factors
- Score capping
- Full dashboard integration

At the time of completion, all **12 tests passed**.

Run a compilation check:

```bash
python -m compileall main.py dashboard tests
```

Check for whitespace errors before committing:

```bash
git diff --check
```

## Sample Data

The current version reads demonstration data from:

```text
data/sample_data.json
```

The sample data may include:

- Assets
- Helpdesk tickets
- Remediation tickets
- Vulnerabilities
- Vulnerability scans
- Security alerts

The JSON file must contain valid JSON. Validate it with:

```bash
python -m json.tool data/sample_data.json >/dev/null
echo $?
```

An output of `0` means the JSON is valid.

## Security and Safe Use

This project is intended for defensive security learning and authorized environments only.

- Scan only systems you own or have explicit permission to test.
- Do not expose vulnerable applications directly to the public internet.
- Do not commit secrets, passwords, API keys, tokens, or `.env` files.
- Do not use Flask's development server for a public production deployment.
- Use a production WSGI server and secure reverse proxy when deploying.

## Planned Integration

The dashboard is part of a larger IT Operations Suite:

```text
IT Operations Suite
├── IT Helpdesk and Asset System
├── Network Vulnerability Scanner
├── IT Security Dashboard
└── Security Log Analyzer
```

Future work can include:

- Live integration with the helpdesk and asset system
- Direct scanner JSON imports
- PostgreSQL storage
- User authentication and roles
- Historical charts and trends
- Real-time log-analyzer alerts
- Docker deployment
- Deployment to the CyberLab Ubuntu server

## Related Projects

### IT Helpdesk and Asset System

Repository:

```text
https://github.com/Muhtasim19/it-helpdesk-asset-system
```

Live demo:

```text
https://it-helpdesk-asset-system-1.onrender.com/login
```

### Network Vulnerability Scanner

Repository:

```text
https://github.com/Muhtasim19/network-vulnerability-scanner
```

## Authors

- Muhtasim
- Sabirul

## License

See the `LICENSE` file in this repository.
