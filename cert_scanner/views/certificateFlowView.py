import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session, joinedload
from ..models import Application, CertificateBinding
from ..constants import platform_options
from ..static.styles import load_warning_suppression, load_css


def render_certificate_flow_view(engine):
    """Render the certificate flow visualization view"""
    # Load warning suppression script and CSS
    load_warning_suppression()
    load_css()
    
    st.title("Certificate Flow")
    
    with Session(engine) as session:
        # Get all applications with certificate bindings
        applications = session.query(Application).options(
            joinedload(Application.suite),
            joinedload(Application.certificate_bindings)
            .joinedload(CertificateBinding.certificate)
        ).all()
        
        if not applications:
            st.warning("No applications found")
            return
        
        # Filter applications with certificate bindings
        apps_with_bindings = [
            app for app in applications 
            if app.certificate_bindings
        ]
        
        if not apps_with_bindings:
            st.warning("No certificate flows found")
            return
        
        # Application selection
        app_options = {
            f"{app.suite.name} - {app.name}" if app.suite else app.name: app.id 
            for app in apps_with_bindings
        }
        
        selected_app = st.selectbox(
            "Select Application",
            options=list(app_options.keys()),
            format_func=lambda x: x
        )
        
        if selected_app:
            app = next(
                (app for app in apps_with_bindings if app.id == app_options[selected_app]),
                None
            )
            if app:
                render_flow_diagram(app)
                render_flow_details(app)

def render_flow_diagram(app):
    """Render Mermaid diagram for certificate flow"""
    st.subheader("Certificate Flow Diagram")
    
    # Group bindings by order
    ordered_bindings = {}
    for binding in app.certificate_bindings:
        order = binding.binding_order or 999
        if order not in ordered_bindings:
            ordered_bindings[order] = []
        ordered_bindings[order].append(binding)
    
    # Create Mermaid diagram
    mermaid_code = """
    %%{
      init: {
        'theme': 'base',
        'themeVariables': {
          'primaryColor': '#2196f3',
          'primaryTextColor': '#fff',
          'primaryBorderColor': '#2196f3',
          'lineColor': '#2196f3',
          'secondaryColor': '#006db3',
          'tertiaryColor': '#fff'
        }
      }
    }%%
    graph LR
    """
    
    # Add nodes and connections
    prev_nodes = []
    for order in sorted(ordered_bindings.keys()):
        current_nodes = []
        for binding in ordered_bindings[order]:
            node_id = f"{binding.platform}_{binding.id}"
            node_label = (
                f"{platform_options.get(binding.platform, binding.platform)}\\n"
                f"{binding.certificate.common_name[:20]}..."
            )
            mermaid_code += f"{node_id}[{node_label}]\n"
            current_nodes.append(node_id)
            
            # Add connections from previous level
            for prev_node in prev_nodes:
                mermaid_code += f"{prev_node} --> {node_id}\n"
        
        prev_nodes = current_nodes
    
    # Display diagram
    st.markdown(f"""
    ```mermaid
    {mermaid_code}
    ```
    """)

def render_flow_details(app):
    """Render detailed information about the certificate flow"""
    st.subheader("Flow Details")
    
    # Group bindings by order
    ordered_bindings = {}
    for binding in app.certificate_bindings:
        order = binding.binding_order or 999
        if order not in ordered_bindings:
            ordered_bindings[order] = []
        ordered_bindings[order].append(binding)
    
    # Display each level
    for order in sorted(ordered_bindings.keys()):
        with st.expander(f"Level {order if order != 999 else 'Unordered'}", expanded=True):
            for binding in ordered_bindings[order]:
                is_valid = binding.certificate.valid_until > datetime.now()
                status_color = "#198754" if is_valid else "#dc3545"
                status_text = "Valid" if is_valid else "Expired"
                
                st.markdown(f"""
                    ### {platform_options.get(binding.platform, binding.platform)}
                    
                    **Certificate:** <span style="color: {status_color}; font-weight: 500">{binding.certificate.common_name}</span>  
                    **Status:** <span style="background-color: {status_color}; color: white; font-weight: 500; padding: 2px 8px; border-radius: 20px">{status_text}</span>  
                    **Valid Until:** {binding.certificate.valid_until.strftime('%Y-%m-%d')}  
                    **Host:** {binding.host.name}  
                    **IP:** {binding.host_ip.ip_address if binding.host_ip else 'N/A'}  
                    **Port:** {binding.port}  
                    **Site Name:** {binding.site_name or 'Default'}
                """, unsafe_allow_html=True)
                
                # Show parent/child relationships
                if binding.parent_binding:
                    st.markdown(f"""
                        **Parent Certificate:** {binding.parent_binding.certificate.common_name}  
                        **Parent Platform:** {platform_options.get(binding.parent_binding.platform, binding.parent_binding.platform)}
                    """)
                
                if binding.child_bindings:
                    child_certs = [
                        f"- {b.certificate.common_name} ({platform_options.get(b.platform, b.platform)})"
                        for b in binding.child_bindings
                    ]
                    st.markdown("**Child Certificates:**")
                    st.markdown("\n".join(child_certs))
                
                st.divider() 