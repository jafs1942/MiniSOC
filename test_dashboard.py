
import streamlit as st

st.set_page_config(
    page_title="Mini SOC Test",
    layout="wide"
)

st.title("MINI SOC - SYSTEM TEST")

st.success("Streamlit is working!")

st.metric("Test Alerts", 1)

st.write("If you can see this page, the Streamlit interface is rendering correctly.")
