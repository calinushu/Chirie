# Ceahlau 43/2

A small private expense tracker for a rented apartment. It uses Python standard library + SQLite, so deployment is simple and there are no paid services or external dependencies.

## Features

- Admin login created on first start from environment variables.
- Admin can create tenant users and additional admins.
- Admin can create tenancy periods with start/end dates and move-in/move-out gas and electricity readings.
- Tenants can view only the records assigned to their tenancy periods: current amount to pay, rent, utility history, readings, trends, and bill attachments.
- Only admins can add bills, configure rent, manage tenancies, edit entries, create users, or mark items paid/unpaid.
- Admins can record partial payments against rent, charges, and utility bills.
- Rent is configured once as a recurring monthly charge with a configurable due day.
- Utility records for electricity, gas, common bills, and internet.
- Utility readings support actual readings, estimates, corrections/credits, meter rollover, and final move-out readings.
- Monthly history with previous/current readings, calculated consumption, due dates, notes, and bill images/PDFs.
- SQLite database and uploads stored in a persistent `data` volume.

## Run Locally

```bash
python app.py
```

Open `http://127.0.0.1:8000`.

Default first-run admin credentials, unless overridden:

- Email: `admin@example.com`
- Password: `ChangeMe123!`

Change these before deploying.

## Docker

```bash
docker compose up -d --build
```

The app listens on port `8000`.

## Coolify Notes

Use this repository as a Docker Compose app. Set these environment variables in Coolify:

```env
APP_NAME=Ceahlau 43/2
APARTMENT_NAME=Ceahlau 43/2
ADMIN_NAME=Your Name
ADMIN_EMAIL=you@example.com
ADMIN_PASSWORD=use-a-long-random-password
COOKIE_SECURE=1
DATA_DIR=/app/data
PORT=8000
```

Keep the named volume `chirie-data` or map `/app/data` to persistent storage. That folder contains:

- `chirie.sqlite3`
- uploaded bill files under `uploads/`

If you change `ADMIN_EMAIL` or `ADMIN_PASSWORD` after the first run, existing accounts are not overwritten. Log in with the current admin and create/change users from the app.
