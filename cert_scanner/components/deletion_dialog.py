import streamlit as st
from typing import Optional, List, Dict, Any

def render_deletion_dialog(
    title: str,
    item_name: str,
    dependencies: Dict[str, List[str]],
    on_confirm: callable,
    danger_text: Optional[str] = None
) -> None:
    """
    Renders a standardized deletion confirmation dialog.
    
    Args:
        title: Dialog title (e.g., "Delete Certificate")
        item_name: Name of item being deleted
        dependencies: Dict of related items that will be affected
        on_confirm: Callback function to execute on confirmation
        danger_text: Optional additional warning text
    """
    with st.expander("🗑️ Delete", expanded=False):
        st.warning(f"⚠️ You are about to delete: **{item_name}**")
        
        # Show dependencies if any exist
        if dependencies:
            st.markdown("#### This will affect:")
            for dep_type, items in dependencies.items():
                if items:
                    st.markdown(f"**{dep_type}** ({len(items)})")
                    for item in items:
                        st.markdown(f"- {item}")
        
        # Show additional danger text if provided
        if danger_text:
            st.error(danger_text)
        
        # Require explicit confirmation
        confirm_text = f"delete {item_name}"
        confirmation = st.text_input(
            "Type the confirmation text to enable deletion",
            key=f"confirm_delete_{item_name}",
            help=f"Type exactly: {confirm_text}",
            placeholder=confirm_text
        )
        
        # Delete button - only enabled if confirmation matches
        st.button(
            "Delete",
            type="secondary",
            disabled=confirmation != confirm_text,
            on_click=on_confirm if confirmation == confirm_text else None,
            key=f"delete_button_{item_name}"
        ) 