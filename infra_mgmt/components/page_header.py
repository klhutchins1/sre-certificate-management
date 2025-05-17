import streamlit as st

def render_page_header(
    title: str,
    button_label: str = None,
    button_callback=None,
    button_type: str = "primary",
    button_disabled: bool = False,
    button_key: str = None,
    extra_right=None,
    divider: bool = True,
):
    """
    Renders a standardized page header with a title and optional right-aligned button.

    Args:
        title (str): The page title.
        button_label (str, optional): Label for the right-aligned button.
        button_callback (callable, optional): Function to call when button is clicked.
        button_type (str, optional): Streamlit button type ("primary", "secondary").
        button_disabled (bool, optional): Whether the button is disabled.
        button_key (str, optional): Unique key for the button.
        extra_right (callable, optional): Function to render extra content in the right column.
        divider (bool, optional): Whether to show a divider below the header.
    """
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"<h1 style='margin-bottom:0.5rem'>{title}</h1>", unsafe_allow_html=True)
    with col2:
        if button_label:
            st.button(
                button_label,
                on_click=button_callback,
                type=button_type,
                disabled=button_disabled,
                key=button_key,
                use_container_width=True
            )
        else:
            # Render an invisible button-sized placeholder for alignment
            st.markdown("<div style='height:38px;'></div>", unsafe_allow_html=True)
    if divider:
        st.divider() 