# VulneraPred Web GUI

Modern web-based interface for the VulneraPred vulnerability detection system.

## Features

- **Modern UI**: Clean, responsive design with gradient styling
- **Real-time Analysis**: Fast vulnerability detection with live feedback
- **Interactive Results**: Detailed vulnerability reports with color-coded severity
- **Code Editor**: Syntax-highlighted code input with line/character counts
- **Example Code**: Load pre-built vulnerable code examples
- **Responsive Design**: Works on desktop, tablet, and mobile devices

## Technology Stack

- **Backend**: Flask (Python web framework)
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Icons**: Font Awesome 6
- **Styling**: Custom CSS with CSS Grid and Flexbox

## Installation

1. **Install Flask** (if not already installed):
   ```bash
   pip install flask
   ```

2. **Navigate to Web GUI directory**:
   ```bash
   cd "Web GUI"
   ```

## Running the Application

1. **Start the Flask server**:
   ```bash
   python app.py
   ```

2. **Open your browser** and navigate to:
   ```
   http://localhost:5000
   ```

3. **Start analyzing code!**

## Usage

1. **Enter Code**:
   - Paste Python code into the editor
   - Or click "Example" to load vulnerable code sample
   - Watch the line/character count update in real-time

2. **Analyze**:
   - Click "Analyze Code" button
   - Wait for analysis (typically < 2 seconds)
   - View comprehensive results on the right panel

3. **Review Results**:
   - **Status Cards**: Quick overview (Status, Confidence, Priority, Time)
   - **Code Statistics**: Metrics about your code
   - **Vulnerabilities**: Detailed list of detected issues
   - **Risk Assessment**: Multi-factor risk analysis
   - **Recommendations**: Actionable security advice

## Features Explained

### Status Indicators
- 🔴 **VULNERABLE**: Security issues detected
- 🟢 **SAFE**: No vulnerabilities found
- **Confidence**: ML model confidence (0-100%)
- **Priority**: CRITICAL, HIGH, MEDIUM, or LOW

### Vulnerability Detection
- **Pattern Matching**: Regex-based detection
- **AST Analysis**: Semantic code analysis
- **ML Classification**: AI-powered detection
- **Severity Levels**: CRITICAL, HIGH, MEDIUM, LOW

### Risk Factors
- Code Complexity
- Dangerous Functions
- Input Handling
- Error Handling
- Authentication

## API Endpoints

### `GET /`
Returns the main HTML page.

### `GET /api/status`
Check if models are loaded.

**Response**:
```json
{
  "models_loaded": true,
  "timestamp": "2025-12-09T12:00:00"
}
```

### `POST /api/analyze`
Analyze code for vulnerabilities.

**Request Body**:
```json
{
  "code": "def login(user):\n    query = f\"SELECT * FROM users WHERE user='{user}'\""
}
```

**Response**:
```json
{
  "success": true,
  "is_vulnerable": true,
  "confidence": 95.5,
  "urgency_score": 85.0,
  "analysis_time": 1.23,
  "vulnerabilities": [...],
  "statistics": {...},
  "risk_factors": {...},
  "recommendations": [...]
}
```

## Directory Structure

```
Web GUI/
├── app.py                 # Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── static/
│   ├── css/
│   │   └── style.css     # Application styles
│   └── js/
│       └── app.js        # Frontend JavaScript
└── templates/
    └── index.html        # Main HTML template
```

## Customization

### Changing Colors
Edit `static/css/style.css` and modify the CSS variables:
```css
:root {
    --primary: #2196F3;        /* Change primary color */
    --primary-dark: #1976D2;
    --success: #4CAF50;
    --danger: #F44336;
    /* ... */
}
```

### Changing Port
Edit `app.py` and modify the last line:
```python
app.run(debug=True, host='0.0.0.0', port=5000)  # Change port here
```

## Browser Support

- Chrome/Edge (recommended)
- Firefox
- Safari
- Opera

## Performance

- Average analysis time: < 2 seconds
- Handles code files up to 16MB
- Real-time code statistics update
- Smooth animations and transitions

## Security Notes

- The web server binds to `0.0.0.0` (all interfaces)
- For production, use proper WSGI server (gunicorn, uWSGI)
- Implement authentication for public deployments
- Use HTTPS in production environments

## Troubleshooting

### Models not loading
- Ensure the parent `models/` directory exists
- Check that model files (.pkl) are present
- Verify parent directory path in `app.py`

### Port already in use
- Change the port in `app.py`
- Or kill the process using port 5000

### Analysis fails
- Check Flask console for error messages
- Ensure all parent dependencies are installed
- Verify Python version compatibility

## Future Enhancements

- File upload functionality
- Dark/light theme toggle
- Export reports as PDF
- Historical analysis tracking
- Batch analysis support
- Real-time collaboration features

## License

Part of the VulneraPred project - CS Course Introduction to AI

## Support

For issues or questions, please refer to the main project documentation.
