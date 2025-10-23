Who Might Get Along? — quick deploy notes

This Streamlit app is designed for a one-day classroom/demo event. It includes:
- One admin password + 20 student passwords (auto-generated on first run and saved to `credentials.json`).
- Student login (each student password is single-use).
- Upload limit: up to 2 images per student (keeps AI costs low).

Quick files added:
- `requirements.txt` — Python dependencies for deployment.
- `credentials.json` — generated on first run (created by the app). The admin password is printed to the process console when credentials are initialized.

Free hosting options (recommended order)

1) Streamlit Community Cloud (recommended for Streamlit apps)
- Pros: built for Streamlit, free for public apps, easy deployment from GitHub repo.
- Cons: apps are public unless you use a paid plan; file-system persistence may be ephemeral between runs.

Steps:
1. Push this repo to GitHub.
2. Go to https://share.streamlit.io and sign in with GitHub.
3. Create a new app, point it to the repo and select `app.py` as the main file.
4. Add any required secrets (optional): in the app you can set `OPENAI_API_KEY` via Streamlit Secrets if you want AI enabled. Alternatively disable AI in the sidebar to avoid costs.

Notes about admin password on Streamlit Cloud:
- On first startup the app will generate `credentials.json` and print the admin password to the process logs. To retrieve it:
  - Go to your Streamlit Cloud app dashboard -> "View logs" and look for the line starting with `[INIT] Admin password generated...`.
  - Alternatively, run the app locally first (see below) to capture the password before deploying.

2) Replit
- Pros: simple, interactive, free plan supports running a Flask/Streamlit app and exposing a public URL.
- Cons: may require small tweaks in run command, and free plan has inactive-sleep behavior.

Steps:
1. Create a new Replit from your GitHub repo or upload files.
2. Use the package manager to install requirements (or include `requirements.txt`).
3. Start the app with `streamlit run app.py`.
4. Replit will provide a public URL.

3) Quick local exposure with ngrok (no deployment)
- Pros: fastest for a one-off demo; no need to push code to any host.
- Cons: tunneling external service; free tier URLs change each run; requires running the app locally during the talk.

Steps:
1. Run the app locally:

```powershell
python -m pip install -r requirements.txt
streamlit run app.py
```

2. Download and run ngrok (https://ngrok.com). Expose the local Streamlit port (default 8501):

```powershell
ngrok http 8501
```

3. Share the public ngrok URL with your students.

Security & cost notes
- AI (OpenAI) calls cost money. To avoid costs, disable AI in the sidebar or do not set `st.session_state.openai_api_key`.
- Limit uploads to 2 images per student to keep usage low (implemented in the app).
- The credentials file stores plaintext passwords for convenience because this is a short-lived demo. Don't use this approach for production apps.

How to get admin password (recommended)
- Run the app locally once. On first run the app prints the admin password to the console and writes `credentials.json` in the repo directory.
- Example:

```powershell
python -m pip install -r requirements.txt
streamlit run app.py
# check the terminal logs for: [INIT] Admin password generated and saved to <path>: <admin_pw>
```

If you'd like, I can:
- Add a small admin page that displays the admin password (protected) or lets you reset the student passwords.
- Help push this project to GitHub and configure Streamlit Community Cloud or Replit.

Next steps I can do now
- Create a small README note on how to retrieve credentials after deploying to Streamlit Cloud.
- Add an optional endpoint to regenerate student passwords (admin-only).
- Help you push to GitHub and walk through Streamlit Cloud deployment interactively.
