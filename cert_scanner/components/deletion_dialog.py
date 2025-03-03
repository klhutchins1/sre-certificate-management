"""
Deletion Dialog Component

A reusable component for handling entity deletion with confirmation,
dependency checking, and consistent UI patterns.

Provides two main interfaces:
1. render_deletion_dialog: For simple deletion confirmations
2. render_danger_zone: For complex deletions with dependencies
"""

import streamlit as st
from typing import Dict, List, Callable, Optional, Any
from sqlalchemy.orm import Session

def render_deletion_dialog(
    title: str,
    item_name: str,
    dependencies: Dict[str, List[str]],
    on_confirm: Callable[[], None],
    danger_text: Optional[str] = None
) -> None:
    """Legacy deletion dialog - maintained for backward compatibility"""
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

def render_danger_zone(
    title: str,
    entity_name: str,
    entity_type: str,
    dependencies: Dict[str, List[str]],
    on_delete: Callable[[Session], bool],
    session: Session,
    custom_warning: Optional[str] = None
) -> None:
    """
    Renders a standardized danger zone section for entity deletion.
    
    Args:
        title: Title for the danger zone section
        entity_name: Name of the entity being deleted
        entity_type: Type of entity (e.g., "host", "certificate", "domain")
        dependencies: Dictionary of dependency types and their values
        on_delete: Callback function that handles the actual deletion
        session: SQLAlchemy session
        custom_warning: Optional custom warning message
    """
    with st.expander("⚠️ Danger Zone", expanded=False):
        st.markdown(f"### {title}")
        
        # Show dependencies if any exist
        has_dependencies = any(deps for deps in dependencies.values())
        if has_dependencies:
            st.warning("The following items will also be deleted:")
            for dep_type, dep_items in dependencies.items():
                if dep_items:
                    st.markdown(f"**{dep_type}:**")
                    for item in dep_items:
                        st.markdown(f"- {item}")
        
        # Warning message
        warning_text = custom_warning or f"This action cannot be undone. This will permanently delete the {entity_type} '{entity_name}' and all related data."
        st.warning(warning_text)
        
        # Confirmation input
        confirm_text = f"delete {entity_name}"
        confirmation = st.text_input(
            f"Please type '{confirm_text}' to confirm deletion",
            key=f"confirm_delete_{entity_type}_{entity_name}"
        )
        
        # Delete button
        if st.button("Delete", type="secondary", key=f"delete_{entity_type}_{entity_name}"):
            if confirmation == confirm_text:
                try:
                    if on_delete(session):
                        st.success(f"{entity_type.title()} deleted successfully!")
                        st.rerun()
                except Exception as e:
                    st.error(f"Error deleting {entity_type}: {str(e)}")
            else:
                st.error("Confirmation text doesn't match. Please try again.") 