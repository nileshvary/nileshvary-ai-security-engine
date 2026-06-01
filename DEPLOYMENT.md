# RemediAX Deployment Checklist

## Local development

1. Install everything (CLI engine + webapp extras + dev tools):
   ```
   pip install -e ".[dev,webapp]"
   ```
2. Bootstrap an admin token:
   ```
   python generate_token.py --duration permanent --for "Admin"
   ```
3. Save the printed token somewhere safe — it will not be shown again.
4. Run the app locally:
   ```
   streamlit run app.py
   ```
   Open the printed URL and paste the token to log in.

## Streamlit Community Cloud

5. Push to GitHub. Confirm `tokens.json`, `.remediax_usage.json`, `.streamlit/secrets.toml`, and `_remediax_runs/` are all gitignored.
6. Connect the repo to https://share.streamlit.io.
7. In the Streamlit Cloud dashboard, set Secrets:
   ```
   ANTHROPIC_API_KEY = "sk-ant-..."     # optional, only needed for app-side Claude calls
   APP_ADMIN_TOKEN   = "<the token from step 2>"
   ```
8. Restrict access via the Streamlit sharing email whitelist (Settings → Sharing).
9. Share the public URL plus per-user tokens generated with `python generate_token.py --duration 48h --for "<name>"`. Tokens are time-limited; rotate as needed.
