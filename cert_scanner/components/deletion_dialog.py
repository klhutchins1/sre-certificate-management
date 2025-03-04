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
from ..notifications import notify

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
    custom_warning: Optional[str] = None,
    additional_actions: Optional[List[Dict[str, Any]]] = None
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
        additional_actions: Optional list of additional danger zone actions
            Each action should be a dict with:
            - title: str - Button text
            - callback: Callable - Function to call when button is clicked
            - warning: Optional[str] - Warning message to show
            - confirmation_required: bool - Whether to require confirmation
            - confirmation_text: Optional[str] - Text to type for confirmation
    """
    with st.expander("⚠️ Danger Zone", expanded=False):
        st.markdown(f"### {title}")
        
        # Show additional actions first if any
        if additional_actions:
            for i, action in enumerate(additional_actions):
                if i > 0:
                    st.markdown("---")
                
                # Create columns for better layout
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"#### {action['title']}")
                    if action.get("warning"):
                        st.markdown(f"_{action['warning']}_")
                    
                    # Handle confirmation if required
                    confirmed = True
                    if action.get("confirmation_required"):
                        confirm_text = action.get("confirmation_text", f"confirm {action['title'].lower()}")
                        confirmation = st.text_input(
                            f"Type '{confirm_text}' to confirm",
                            key=f"confirm_{action['title'].lower()}_{entity_name}"
                        )
                        confirmed = confirmation == confirm_text
                
                with col2:
                    # Use the action's title for the button
                    if st.button(
                        action["title"],
                        type="secondary",
                        key=f"{action['title'].lower()}_{entity_name}",
                        disabled=action.get("confirmation_required") and not confirmed
                    ):
                        if not confirmed and action.get("confirmation_required"):
                            notify("Please type the confirmation text exactly as shown.", "warning")
                        else:
                            action["callback"](session)
        
        # Add separator before deletion section
        st.markdown("---")
        
        # Deletion section
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("### Permanent Deletion")
            
            # Show dependencies if any exist
            has_dependencies = any(deps for deps in dependencies.values())
            if has_dependencies:
                st.markdown("**The following items will also be deleted:**")
                for dep_type, dep_items in dependencies.items():
                    if dep_items:
                        st.markdown(f"**{dep_type}:**")
                        for item in dep_items:
                            st.markdown(f"- {item}")
            
            # Warning message as markdown
            warning_text = custom_warning or f"_This action cannot be undone. This will permanently delete the {entity_type} '{entity_name}' and all related data._"
            st.markdown(warning_text)
            
            # Confirmation input
            confirm_text = f"delete {entity_name}"
            confirmation = st.text_input(
                f"Type '{confirm_text}' to confirm deletion",
                key=f"confirm_delete_{entity_type}_{entity_name}"
            )
        
        with col2:
            # Delete button
            if st.button(
                "🗑️ Delete Permanently",
                type="secondary",
                key=f"delete_{entity_type}_{entity_name}",
                disabled=confirmation != confirm_text
            ):
                if confirmation == confirm_text:
                    try:
                        if on_delete(session):
                            notify(f"{entity_type.title()} deleted successfully!", "success")
                            st.rerun()
                    except Exception as e:
                        notify(f"Error deleting {entity_type}: {str(e)}", "error")
                else:
                    notify("Please type the confirmation text exactly as shown.", "warning") 