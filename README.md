# Security Project Portfolio

Dependency-free static portfolio prepared for GitHub Pages.

## Local preview

```powershell
python -m http.server 8080
```

Open `http://127.0.0.1:8080`.

## Before public publishing

1. Review every project claim against repository evidence.
2. Run a secret scan on this repository and each linked project.
3. Publish the project repositories and replace local-only status with their real URLs.
4. Enable GitHub Pages with GitHub Actions as the source.
5. Add the final HTTPS URL to `data/base_cv.json`; do not add a placeholder URL.

