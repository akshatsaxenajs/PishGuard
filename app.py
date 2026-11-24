
import streamlit as st
import pandas as pd
import joblib

from pathlib import Path
from modules.url_analyzer import analyze_url, assess_url_risk
from modules.threat_database import initialize_database, check_threat
from modules.scan_history import initialize_scan_history, save_scan, get_scan_history

initialize_database()
initialize_scan_history()

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "phishing_model.joblib"

st.set_page_config(
    page_title="PhishGuard | URL Security",
    page_icon="🛡️",
    layout="wide"
)


@st.cache_resource
def load_model():
    return joblib.load(MODEL_PATH)


st.title("🛡️ PhishGuard")
st.subheader("AI-Assisted Phishing URL Detection System")

st.markdown("---")

st.write(
    "Analyze suspicious URLs using Machine Learning "
    "and URL security indicators."
)

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Model Status", "Active")

with col2:
    st.metric("Training URLs", "235,370")

with col3:
    st.metric("Test Accuracy", "99.47%")

st.markdown("---")

st.header("🔍 URL Scanner")

url = st.text_input(
    "Enter a URL to analyze",
    placeholder="https://example.com"
)


if st.button("Analyze URL", type="primary"):

    if not url.strip():
        st.warning("Please enter a URL.")

    else:
        try:
            features = analyze_url(url)
            risk_result = assess_url_risk(features)
            database_result = check_threat(url)

            model = load_model()

            prediction = int(model.predict([url.strip()])[0])
            probabilities = model.predict_proba([url.strip()])[0]
            phishing_index = list(model.classes_).index(1)
            phishing_probability = probabilities[phishing_index]

            prediction_label = (
                "Phishing" if prediction == 1 else "Legitimate"
            )

            save_scan(
                url.strip(),
                prediction_label,
                float(phishing_probability) * 100,
                risk_result["risk_level"]
            )
            
            # Local Threat Database Result
            st.subheader("🗄️ Local Threat Database Result")

            if database_result["found"]:
                st.error(
                    f"Known Threat Found: {database_result['threat_type']}"
                )
                st.write(f"Source: {database_result['source']}")

            else:
                st.info("URL not found in local threat database.")
                st.caption(
                    "This does not guarantee that the URL is safe."
                )

            # URL Risk Analysis Result
            st.subheader("⚠️ URL Risk Analysis")

            if risk_result["risk_level"] == "High Risk":
                st.error(f"Risk Level: {risk_result['risk_level']}")

            elif risk_result["risk_level"] == "Medium Risk":
                st.warning(f"Risk Level: {risk_result['risk_level']}")

            else:
                st.success(f"Risk Level: {risk_result['risk_level']}")

            st.metric(
                "Risk Score",
                f"{risk_result['risk_score']} / 12"
            )

            st.write("Risk Factors:")

            if risk_result["risk_factors"]:
                for factor in risk_result["risk_factors"]:
                    st.write(f"• {factor}")
            else:
                st.write("No risk indicators detected.")

            # ML Detection Result
            st.subheader("🛡️ ML Detection Result")

            if prediction == 1:
                st.error("⚠️ Potential Phishing URL Detected")
            else:
                st.success("No phishing pattern detected by the model")

            st.metric(
                "Model Phishing Score",
                f"{phishing_probability * 100:.2f}%"
            )

            st.caption(
                "This score is the model's estimated probability, "
                "not a guarantee of actual safety."
            )

            # URL Feature Analysis
            st.subheader("📊 URL Feature Analysis")

            results = pd.DataFrame(
                list(features.items()),
                columns=["Feature", "Value"]
            )

            st.dataframe(
                results,
                width="stretch",
                hide_index=True
            )

        except ValueError as error:
            st.error(str(error))

        except Exception as error:
            st.error(f"Analysis error: {error}")


st.markdown("---")

st.header("📜 Scan History")

history = get_scan_history()

if history:
    total_scans = len(history)
    phishing_count = sum(
        1 for row in history if row[2] == "Phishing"
    )
    legitimate_count = sum(
        1 for row in history if row[2] == "Legitimate"
    )

    stat1, stat2, stat3 = st.columns(3)

    stat1.metric("Total URLs Scanned", total_scans)
    stat2.metric("Phishing URLs", phishing_count)
    stat3.metric("Legitimate URLs", legitimate_count)

    chart_data = pd.DataFrame({
        "Category": ["Phishing", "Legitimate"],
        "Count": [phishing_count, legitimate_count]
    })

    st.subheader("📊 Scan Distribution")

    st.bar_chart(
        chart_data,
        x="Category",
        y="Count"
    )
    history_df = pd.DataFrame(
        history,
        columns=[
            "ID",
            "URL",
            "Prediction",
            "Phishing Score (%)",
            "Risk Level",
            "Scan Time"
        ]
    )

    st.dataframe(
        history_df,
        width="stretch",
        hide_index=True
    )

    csv_data = history_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="📥 Download Scan Report (CSV)",
        data=csv_data,
        file_name="PhishGuard_Scan_Report.csv",
        mime="text/csv"
    )

else:
    st.info("No scan history available yet.")

st.markdown("---")

st.caption("PhishGuard | Cybersecurity Mini Project")
