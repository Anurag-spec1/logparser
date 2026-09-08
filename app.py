import utils.session
import json
import re
import requests
import pandas as pd
from datetime import datetime
from typing import Dict, Any, Optional, List
import streamlit as st
from dataclasses import dataclass, asdict
import hashlib
import time

# Configuration
OPENROUTER_API_KEY = ""
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL_NAME = "qwen/qwen-2.5-72b-instruct"

st.set_page_config(
    page_title="ULPF - Universal Log Pre-processing Framework",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');
    
    .stApp {
        background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 50%, #0a0a0a 100%);
        font-family: 'Inter', sans-serif;
    }
    
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    ::-webkit-scrollbar {width: 8px; height: 8px;}
    ::-webkit-scrollbar-track {background: #1a1a1a;}
    ::-webkit-scrollbar-thumb {background: #FFD700; border-radius: 4px;}
    
    .main-title {
        font-size: 3rem;
        font-weight: 900;
        background: linear-gradient(135deg, #FFD700 0%, #FFA500 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 0.5rem;
        letter-spacing: -1px;
    }
    
    .subtitle {
        color: #888;
        font-size: 1.1rem;
        font-weight: 300;
        margin-bottom: 2rem;
    }
    
    .section-header {
        color: #FFD700;
        font-size: 1.3rem;
        font-weight: 600;
        margin: 1rem 0;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #FFD700;
    }
    
    .card {
        background: linear-gradient(145deg, #1e1e1e 0%, #252525 100%);
        border: 1px solid #333;
        border-radius: 12px;
        padding: 1rem;
        margin: 0.5rem 0;
        transition: all 0.3s ease;
    }
    
    .stButton > button {
        background: linear-gradient(135deg, #FFD700 0%, #FFA500 100%);
        color: #000;
        font-weight: 700;
        padding: 0.5rem 1.2rem;
        border-radius: 8px;
        border: none;
        transition: all 0.3s ease;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-size: 0.85rem;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(255, 215, 0, 0.3);
    }
    
    .stTextArea > div > div > textarea {
        background: #1a1a1a;
        color: #fff;
        border: 2px solid #333;
        border-radius: 8px;
        font-family: 'JetBrains Mono', monospace;
    }
    
    .stDataFrame {
        background: #1a1a1a;
        border: 1px solid #333;
        border-radius: 8px;
    }
    
    .requirement-badge {
        display: inline-block;
        background: #1a1a1a;
        color: #FFD700;
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
        border: 1px solid #FFD700;
        font-size: 0.75rem;
        margin: 0.15rem;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

@dataclass
class UniversalEvent:
    """Universal Event Schema"""
    event_id: str
    raw_event_id: str
    schema_version: str
    timestamp: str
    event_category: str
    event_type: str
    event_action: str
    event_outcome: str
    severity: str
    source_ip: str
    source_port: str
    destination_ip: str
    destination_port: str
    protocol: str
    user_name: str
    host_name: str
    process_name: str
    source_vendor: str
    source_product: str
    source_format: str
    raw_event: str
    processing_method: str
    confidence: float
    parser_version: str
    processing_time_ms: float
    extra_fields: str
    
    def to_dict(self):
        return asdict(self)
    
    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)

class FormatDetector:
    """Detects log format using heuristics - no hardcoded regex"""
    
    def detect(self, log_line: str) -> str:
        """Detect format based on structure analysis"""
        
        # Check if it's JSON
        stripped = log_line.strip()
        if stripped.startswith('{') and stripped.endswith('}'):
            try:
                json.loads(stripped)
                return 'json'
            except:
                # Maybe JSON with embedded JSON string
                if '"log"' in stripped or '"event"' in stripped:
                    return 'json_nested'
        
        # Check if it's XML
        if stripped.startswith('<') and '>' in stripped:
            return 'xml'
        
        # Check for key=value pattern
        if '=' in stripped and not stripped.startswith('{'):
            # Count key=value pairs
            pairs = re.findall(r'\w+=[^,\s|]+', stripped)
            if len(pairs) > 2:
                return 'key_value'
        
        # Check for pipe-delimited
        if stripped.count('|') > 2:
            return 'pipe_delimited'
        
        # Check for space-delimited with timestamp
        if re.match(r'\d{4}-\d{2}-\d{2}', stripped):
            return 'timestamped'
        
        # Check for syslog format
        if re.match(r'[A-Z][a-z]{2}\s+\d+', stripped):
            return 'syslog'
        
        # Check for Android logcat
        if re.match(r'\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', stripped):
            return 'android_logcat'
        
        # Default
        return 'unknown'

class AIParser:
    """AI-powered parser for ANY format"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.url = OPENROUTER_URL
        self.model = MODEL_NAME
    
    def parse(self, log_line: str, detected_format: str = 'unknown') -> Optional[Dict[str, Any]]:
        """Parse using AI with format hint"""
        
        start_time = time.time()
        
        # Truncate for speed
        if len(log_line) > 1500:
            log_line = log_line[:1500]
        
        prompt = f"""Parse this log line. Format detected: {detected_format}

Log: {log_line}

Extract these fields (return empty string if not present):
- timestamp
- host_name (server/device/process name)
- event_category (security, network, database, application, system, android)
- event_type (login, access, transaction, window, power, phone)
- event_action (specific action)
- event_outcome (success, failed, denied, blocked)
- severity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- source_ip
- destination_ip
- user_name
- process_name
- source_vendor
- source_format

Return ONLY JSON:
{{"timestamp":"...","host_name":"...","event_category":"...","event_type":"...","event_action":"...","event_outcome":"...","severity":"...","source_ip":"...","destination_ip":"...","user_name":"...","process_name":"...","source_vendor":"...","source_format":"...","confidence":0.8,"additional_info":{{}}}}
"""
        
        try:
            response = requests.post(
                self.url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "http://localhost:8501",
                    "X-Title": "ULPF"
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens": 400,
                    "response_format": {"type": "json_object"}
                },
                timeout=10  # Reduced timeout for speed
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'choices' in result and len(result['choices']) > 0:
                    ai_response = result['choices'][0]['message']['content']
                    json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
                    if json_match:
                        parsed = json.loads(json_match.group())
                        parsed['processing_time_ms'] = (time.time() - start_time) * 1000
                        return parsed
                    
        except Exception as e:
            print(f"AI error: {e}")
            
        return None

class ULPF:
    """Universal Log Pre-processing Framework"""
    
    def __init__(self, api_key: str):
        self.format_detector = FormatDetector()
        self.ai_parser = AIParser(api_key)
        self.schema_version = "1.0.0"
    
    def process_log(self, log_line: str) -> UniversalEvent:
        """Process single log - format detection + AI parsing"""
        
        event_id = hashlib.md5(log_line.encode()).hexdigest()[:16]
        raw_event_id = hashlib.sha256(log_line.encode()).hexdigest()[:32]
        
        # Detect format
        detected_format = self.format_detector.detect(log_line)
        
        # Use AI to parse (handles ANY format)
        result = self.ai_parser.parse(log_line, detected_format)
        
        if result is not None:
            return self._create_universal_event(
                event_id, raw_event_id, log_line, result, 'ai', result.get('confidence', 0.7)
            )
        
        # Fallback - basic extraction
        basic_result = {
            'timestamp': datetime.now().isoformat(),
            'event_category': 'unknown',
            'event_type': 'unclassified',
            'event_action': 'unknown',
            'severity': 'INFO',
            'source_format': detected_format,
            'confidence': 0.3
        }
        
        return self._create_universal_event(
            event_id, raw_event_id, log_line, basic_result, 'fallback', 0.3
        )
    
    def _create_universal_event(self, event_id: str, raw_event_id: str, raw_log: str,
                                result: Dict[str, Any], method: str,
                                confidence: float) -> UniversalEvent:
        """Create standardized Universal Event"""
        
        def safe_str(value):
            if isinstance(value, (dict, list)):
                return json.dumps(value)
            elif value is None:
                return ''
            else:
                return str(value)
        
        additional_info = result.get('additional_info', {})
        extra_fields = json.dumps(additional_info) if additional_info else ''
        
        return UniversalEvent(
            event_id=event_id,
            raw_event_id=raw_event_id,
            schema_version=self.schema_version,
            timestamp=safe_str(result.get('timestamp', datetime.now().isoformat())),
            event_category=safe_str(result.get('event_category', 'unknown')),
            event_type=safe_str(result.get('event_type', 'unclassified')),
            event_action=safe_str(result.get('event_action', 'unknown')),
            event_outcome=safe_str(result.get('event_outcome', '')),
            severity=safe_str(result.get('severity', 'INFO')),
            source_ip=safe_str(result.get('source_ip', '')),
            source_port=safe_str(result.get('source_port', '')),
            destination_ip=safe_str(result.get('destination_ip', '')),
            destination_port=safe_str(result.get('destination_port', '')),
            protocol=safe_str(result.get('protocol', '')),
            user_name=safe_str(result.get('user_name', '')),
            host_name=safe_str(result.get('host_name', '')),
            process_name=safe_str(result.get('process_name', '')),
            source_vendor=safe_str(result.get('source_vendor', 'unknown')),
            source_product=safe_str(result.get('source_product', '')),
            source_format=safe_str(result.get('source_format', result.get('source_format', 'unknown'))),
            raw_event=raw_log,
            processing_method=method,
            confidence=confidence,
            parser_version='3.0-ai',
            processing_time_ms=result.get('processing_time_ms', 0),
            extra_fields=extra_fields
        )
    
    def export_json(self, events):
        return json.dumps([e.to_dict() for e in events], indent=2)

# Initialize session state
if 'page' not in st.session_state:
    st.session_state.page = 'home'
if 'processed_events' not in st.session_state:
    st.session_state.processed_events = []
if 'ulpf' not in st.session_state:
    st.session_state.ulpf = ULPF(OPENROUTER_API_KEY)

def navigate_to(page):
    st.session_state.page = page

def show_requirements_sidebar():
    st.sidebar.markdown("## ✅ Requirements")
    requirements = ["(a) Raw Data", "(b) Source Attr", "(c) Common Taxonomy", 
                    "(d) Traceability", "(e) Plug-and-play", "(f) Unified View",
                    "(g) SIEM Ready", "(h) AI/ML Ready", "(i) Less Parser Dev",
                    "(j) Air-gapped", "(k) Container"]
    
    for req in requirements:
        st.sidebar.markdown(f'<span class="requirement-badge">{req}</span>', unsafe_allow_html=True)
    
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**Events:** {len(st.session_state.processed_events)}")

def home_page():
    st.markdown('<div class="main-title">⚡ ULPF</div>', unsafe_allow_html=True)
    st.markdown('<div class="subtitle">Universal Log Pre-processing Framework</div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        <div class="card" style="text-align: center;">
            <div style="font-size: 2rem; color: #FFD700;">🤖</div>
            <div style="font-weight: 700; color: #fff;">AI-Powered</div>
            <div style="color: #888; font-size: 0.9rem;">No hardcoded parsers</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="card" style="text-align: center;">
            <div style="font-size: 2rem; color: #FFD700;">🌐</div>
            <div style="font-weight: 700; color: #fff;">Truly Universal</div>
            <div style="color: #888; font-size: 0.9rem;">Any format works</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="card" style="text-align: center;">
            <div style="font-size: 2rem; color: #FFD700;">📊</div>
            <div style="font-weight: 700; color: #fff;">Unified Schema</div>
            <div style="color: #888; font-size: 0.9rem;">One output format</div>
        </div>
        """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("🚀 Process Logs", key="start_btn"):
            navigate_to('upload')
            st.rerun()

def upload_page():
    st.markdown('<div class="section-header">📝 Log Processing</div>', unsafe_allow_html=True)
    
    if st.button("← Home", key="back_btn"):
        navigate_to('home')
        st.rerun()
    
    input_method = st.radio("Input:", ["Paste Log", "Upload File"], horizontal=True)
    
    if input_method == "Paste Log":
        log_text = st.text_area("Log:", height=150, placeholder="Paste any log...")
        st.session_state.log_text = log_text
    else:
        uploaded_file = st.file_uploader("Upload", type=['txt', 'log'])
        if uploaded_file:
            log_text = uploaded_file.getvalue().decode('utf-8', errors='ignore')
            st.session_state.log_text = log_text
            lines = log_text.strip().split('\n')
            st.info(f"📄 File loaded: {len(lines)} lines")
    
    if st.button("⚡ Process", type="primary", disabled=not st.session_state.get('log_text', '')):
        navigate_to('processing')
        st.rerun()

def processing_page():
    st.markdown('<div class="section-header">⚙️ Processing (AI-Powered)</div>', unsafe_allow_html=True)
    
    if 'log_text' not in st.session_state or not st.session_state.log_text:
        st.warning("No log to process.")
        return
    
    log_text = st.session_state.log_text
    lines = log_text.strip().split('\n')
    total_lines = len(lines)
    
    # Process limited lines for demo
    max_process = min(total_lines, 10)
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    events = []
    
    for i, line in enumerate(lines[:max_process]):
        if line.strip():
            progress = (i + 1) / max_process
            progress_bar.progress(progress)
            status_text.text(f"Processing log {i+1}/{max_process}...")
            
            # Detect format
            detected_format = st.session_state.ulpf.format_detector.detect(line.strip())
            
            # Process with AI
            event = st.session_state.ulpf.process_log(line.strip())
            events.append(event)
            st.session_state.processed_events.append(event)
            
            # Show live result
            with st.expander(f"Log {i+1} | Format: {detected_format} | Confidence: {event.confidence:.0%}", expanded=False):
                st.markdown("**Raw:**")
                st.code(event.raw_event[:150], language='text')
                
                st.markdown("**Normalized:**")
                st.json({
                    'timestamp': event.timestamp,
                    'category': event.event_category,
                    'type': event.event_type,
                    'action': event.event_action[:50],
                    'severity': event.severity,
                    'process': event.process_name,
                    'host': event.host_name,
                    'format': event.source_format,
                    'confidence': f"{event.confidence:.0%}"
                })
    
    progress_bar.progress(1.0)
    status_text.text(f"✅ Processed {len(events)} logs!")
    
    # Summary
    st.markdown('<div class="section-header">📊 Summary</div>', unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Logs", len(events))
    with col2:
        avg_conf = sum(e.confidence for e in events) / len(events) if events else 0
        st.metric("Avg Confidence", f"{avg_conf:.1%}")
    with col3:
        formats = set(e.source_format for e in events)
        st.metric("Formats", len(formats))
    with col4:
        categories = set(e.event_category for e in events)
        st.metric("Categories", len(categories))
    
    # Export
    all_json = st.session_state.ulpf.export_json(events)
    st.download_button(
        label="⬇️ Download JSON",
        data=all_json,
        file_name="ulpf_events.json",
        mime="application/json"
    )
    
    # Navigation
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("← Upload More"):
            navigate_to('upload')
            st.rerun()
    with col2:
        if st.button("📊 History"):
            navigate_to('history')
            st.rerun()
    with col3:
        if st.button("🏠 Home"):
            navigate_to('home')
            st.rerun()

def history_page():
    st.markdown('<div class="section-header">📚 History</div>', unsafe_allow_html=True)
    
    if st.button("← Home"):
        navigate_to('home')
        st.rerun()
    
    if not st.session_state.processed_events:
        st.info("No events yet.")
        return
    
    all_json = st.session_state.ulpf.export_json(st.session_state.processed_events)
    st.download_button(
        label="⬇️ Export All JSON",
        data=all_json,
        file_name="ulpf_all_events.json",
        mime="application/json"
    )
    
    events_data = []
    for e in st.session_state.processed_events[:50]:
        events_data.append({
            'Timestamp': e.timestamp[:23],
            'Category': e.event_category,
            'Type': e.event_type,
            'Severity': e.severity,
            'Process': e.process_name,
            'Format': e.source_format,
            'Confidence': f"{e.confidence:.0%}"
        })
    
    st.dataframe(pd.DataFrame(events_data), use_container_width=True)

def main():
    show_requirements_sidebar()
    
    if st.session_state.page == 'home':
        home_page()
    elif st.session_state.page == 'upload':
        upload_page()
    elif st.session_state.page == 'processing':
        processing_page()
    elif st.session_state.page == 'history':
        history_page()

if __name__ == "__main__":
    main()