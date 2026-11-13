# HeaderGuard

HeaderGuard is a passive, local-first audit for HTTP response security headers. It reads a pasted response or saved `curl -I` output and explains the browser protections that are present, weak, or missing. It makes no network requests and does not probe a target.

## Browser dashboard and GitHub Pages

Open `index.html` locally or publish this directory as its own GitHub Pages repository. The included `.github/workflows/pages.yml` deploys the static dashboard from the `main` branch when Pages is configured to use GitHub Actions.

1. Paste an authorized HTTP response or load the synthetic sample.
2. Add an optional target label.
3. Select **Run passive audit**.
4. Review each control and export the JSON report.

## Docker CLI

```sh
docker build -t headerguard .
mkdir -p reports
docker run --rm \
  -v "$PWD/samples:/data:ro" \
  -v "$PWD/reports:/reports" \
  headerguard /data/response.txt --target synthetic.example.test --output /reports/report.json
```

The sample is synthetic. Review only responses you are authorized to inspect. This tool is a posture aid, not a penetration test, compliance certification, or substitute for testing your deployment in context.

## Controls

The baseline covers HSTS, Content-Security-Policy, MIME sniffing, frame protection, referrer policy, Permissions-Policy, session cookie attributes, and server disclosure. The score is a transparent heuristic: pass = 100% of a control, warning = 50%, failure = 0%.

## License

MIT. See [LICENSE](LICENSE).
