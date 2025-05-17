import streamlit as st

def render_metrics_row(metrics, columns=4, divider=True):
    """
    Render a standardized row of metrics.

    Args:
        metrics (list of dict): Each dict should have keys 'label', 'value', and optionally 'delta' and 'help'.
        columns (int): Number of columns to use (default 4).
        divider (bool): Whether to show a divider below the metrics row.
    """
    cols = st.columns(columns)
    for i, metric in enumerate(metrics):
        with cols[i]:
            st.metric(
                label=metric.get('label', ''),
                value=metric.get('value', ''),
                delta=metric.get('delta', None),
                help=metric.get('help', None)
            )
    if divider:
        st.divider() 