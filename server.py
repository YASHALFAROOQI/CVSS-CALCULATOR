"""
CVSS v3.1 Base Score Calculator — Flask app
Run with: python server.py   then open http://127.0.0.1:5000
"""
from flask import Flask, render_template, request
import math

app = Flask(__name__)

AV_W = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_W = {"L": 0.77, "H": 0.44}
UI_W = {"N": 0.85, "R": 0.62}
PR_W_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_W_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
CIA_W = {"H": 0.56, "L": 0.22, "N": 0.0}


def roundup(value: float) -> float:
    """Official CVSS RoundUp function (operates on int(value*100000))."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input // 10000 + 1) / 10.0


def compute_cvss(av, ac, pr, ui, s, c, i, a):
    av_v, ac_v, ui_v = AV_W[av], AC_W[ac], UI_W[ui]
    pr_v = (PR_W_CHANGED if s == "C" else PR_W_UNCHANGED)[pr]
    c_v, i_v, a_v = CIA_W[c], CIA_W[i], CIA_W[a]

    isc_base = 1 - ((1 - c_v) * (1 - i_v) * (1 - a_v))
    if s == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * math.pow(isc_base - 0.02, 15)

    exploitability = 8.22 * av_v * ac_v * pr_v * ui_v

    if impact <= 0:
        base = 0.0
    elif s == "U":
        base = min(impact + exploitability, 10)
    else:
        base = min(1.08 * (impact + exploitability), 10)

    base = roundup(base)

    if base == 0:
        severity = "NONE"
    elif base < 4:
        severity = "LOW"
    elif base < 7:
        severity = "MEDIUM"
    elif base < 9:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    return round(base, 1), severity, vector


@app.route("/", methods=["GET", "POST"])
def index():
    metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"}
    if request.method == "POST":
        for k in metrics:
            metrics[k] = request.form.get(k, metrics[k])

    score, severity, vector = compute_cvss(**{k.lower(): v for k, v in metrics.items()})
    return render_template("index.html", metrics=metrics, score=score, severity=severity, vector=vector)


if __name__ == "__main__":
    app.run(debug=True)
