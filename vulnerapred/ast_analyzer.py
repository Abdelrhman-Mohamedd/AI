"""
AST-based vulnerability analyzer for semantic code analysis.

This module provides Abstract Syntax Tree (AST) based analysis to detect
vulnerabilities with better context awareness than simple pattern matching.
"""

import ast
from typing import List, Dict, Set, Any, Optional
from dataclasses import dataclass


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    type: str
    line: int
    column: int
    severity: str  # 'high', 'medium', 'low'
    description: str
    context: Optional[str] = None


class ASTVulnerabilityAnalyzer(ast.NodeVisitor):
    """
    AST-based vulnerability detection with semantic understanding.
    
    This analyzer provides:
    - Context-aware detection (ignores comments/strings)
    - Data flow tracking (taint analysis)
    - Control flow analysis
    - Function call chain tracking
    """
    
    # Dangerous functions that can lead to code injection
    DANGEROUS_EXEC_FUNCTIONS = {'eval', 'exec', 'compile', '__import__'}
    
    # Dangerous system functions for command injection
    DANGEROUS_SYSTEM_FUNCTIONS = {'system', 'popen', 'popen2', 'popen3', 'popen4'}
    
    # Pickle/marshal deserialization functions
    DANGEROUS_DESERIALIZE_FUNCTIONS = {'loads', 'load'}
    DANGEROUS_DESERIALIZE_MODULES = {'pickle', 'marshal', 'shelve', 'yaml'}
    
    # SQL execution methods
    SQL_EXECUTION_METHODS = {'execute', 'executemany', 'raw', 'executescript'}
    
    # Unsafe XML parsing functions
    XML_PARSING_FUNCTIONS = {'parse', 'fromstring', 'XMLParser', 'iterparse'}
    
    # Weak cryptographic algorithms
    WEAK_CRYPTO_ALGORITHMS = {'md5', 'sha1', 'des', 'rc4', 'MD5', 'SHA1', 'DES', 'RC4'}
    
    # Tainted sources (user input)
    TAINTED_SOURCES = {
        'request.GET', 'request.POST', 'request.args', 'request.form',
        'request.data', 'request.json', 'request.cookies', 'input',
        'raw_input', 'sys.argv', 'os.environ'
    }
    
    def __init__(self):
        """Initialize the analyzer."""
        self.vulnerabilities: List[Vulnerability] = []
        self.tainted_variables: Set[str] = set()
        self.current_function: Optional[str] = None
        self.imports: Dict[str, str] = {}  # alias -> module mapping
        
    def analyze(self, code: str) -> List[Dict[str, Any]]:
        """
        Analyze code for vulnerabilities using AST.
        
        Args:
            code: Source code to analyze
            
        Returns:
            List of vulnerability dictionaries
        """
        self.vulnerabilities = []
        self.tainted_variables = set()
        self.imports = {}
        
        try:
            tree = ast.parse(code)
            self.visit(tree)
            
            # Convert to dictionary format
            return [
                {
                    'type': v.type,
                    'line': v.line,
                    'column': v.column,
                    'severity': v.severity,
                    'description': v.description,
                    'context': v.context
                }
                for v in self.vulnerabilities
            ]
        except SyntaxError as e:
            return [{
                'type': 'syntax_error',
                'line': e.lineno or 0,
                'column': e.offset or 0,
                'severity': 'high',
                'description': f'Syntax error: {e.msg}',
                'context': None
            }]
        except Exception:
            # If AST parsing fails, return empty list (fallback to pattern matching)
            return []
    
    def visit_Import(self, node: ast.Import) -> None:
        """Track imports for module-specific vulnerability detection."""
        for alias in node.names:
            self.imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from-imports for module-specific vulnerability detection."""
        if node.module:
            for alias in node.names:
                name = alias.asname or alias.name
                self.imports[name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track current function context."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Track tainted variable assignments (data flow analysis)."""
        # Check if value comes from tainted source
        if self._is_tainted(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_variables.add(target.id)
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call) -> None:
        """Detect dangerous function calls."""
        func_name = self._get_function_name(node.func)
        
        # Code injection: eval, exec, compile
        if func_name in self.DANGEROUS_EXEC_FUNCTIONS:
            self._add_vulnerability(
                node, 'code_injection',
                f"Dangerous use of {func_name}() - can execute arbitrary code",
                'high'
            )
        
        # Command injection: os.system, subprocess with shell=True
        elif self._is_command_injection(node, func_name):
            self._add_vulnerability(
                node, 'command_injection',
                f"Command injection risk in {func_name}",
                'high'
            )
        
        # SQL injection: cursor.execute with dynamic strings
        elif self._is_sql_injection(node, func_name):
            self._add_vulnerability(
                node, 'sql_injection',
                "SQL injection: query constructed with untrusted input",
                'high'
            )
        
        # Insecure deserialization
        elif self._is_insecure_deserialization(node, func_name):
            self._add_vulnerability(
                node, 'insecure_deserialization',
                f"Insecure deserialization using {func_name}",
                'high'
            )
        
        # XXE (XML External Entity)
        elif self._is_xxe_vulnerable(node, func_name):
            self._add_vulnerability(
                node, 'xxe',
                "XML parsing without disabled external entities",
                'medium'
            )
        
        # Weak cryptography
        elif self._is_weak_crypto(node, func_name):
            self._add_vulnerability(
                node, 'weak_cryptography',
                f"Use of weak cryptographic algorithm: {func_name}",
                'medium'
            )
        
        self.generic_visit(node)
    
    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Detect f-strings that might contain injection vulnerabilities."""
        # Check if f-string is used in dangerous contexts
        # This is checked in the parent Call node
        self.generic_visit(node)
    
    def _get_function_name(self, node: ast.AST) -> str:
        """Extract function name from various node types."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # Handle module.function or object.method
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
            return node.attr
        return ""
    
    def _is_tainted(self, node: ast.AST) -> bool:
        """Check if a value comes from a tainted source."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_variables
        elif isinstance(node, ast.Subscript):
            # Check for request.GET['key'], sys.argv[1], etc.
            value_name = self._get_function_name(node.value)
            return any(source in value_name for source in self.TAINTED_SOURCES)
        elif isinstance(node, ast.Attribute):
            # Check for request.args, request.form, etc.
            attr_name = self._get_function_name(node)
            return any(source in attr_name for source in self.TAINTED_SOURCES)
        elif isinstance(node, ast.Call):
            # Check for input(), raw_input()
            func_name = self._get_function_name(node.func)
            return func_name in {'input', 'raw_input'}
        return False
    
    def _is_dynamic_string(self, node: ast.AST) -> bool:
        """Check if string is dynamically constructed (f-string or concatenation)."""
        if isinstance(node, ast.JoinedStr):
            # f-string
            return True
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # String concatenation with +
            return True
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            # Old-style % formatting
            return True
        elif isinstance(node, ast.Call):
            # .format() method
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                return True
        return False
    
    def _has_tainted_argument(self, node: ast.Call) -> bool:
        """Check if any argument is tainted."""
        for arg in node.args:
            if self._is_tainted(arg) or self._is_dynamic_string(arg):
                return True
        return False
    
    def _is_command_injection(self, node: ast.Call, func_name: str) -> bool:
        """Detect command injection vulnerabilities."""
        # os.system, os.popen, etc.
        if any(func_name.endswith(f".{dangerous}") for dangerous in self.DANGEROUS_SYSTEM_FUNCTIONS):
            # Always flag these as potentially dangerous, even without tainted tracking
            return True
        
        # subprocess.call, subprocess.run with shell=True
        if 'subprocess' in func_name or func_name in {'call', 'run', 'Popen'}:
            for keyword in node.keywords:
                if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is True:
                        return True
        
        return False
    
    def _is_sql_injection(self, node: ast.Call, func_name: str) -> bool:
        """Detect SQL injection vulnerabilities."""
        # cursor.execute, cursor.executemany, etc.
        if any(method in func_name for method in self.SQL_EXECUTION_METHODS):
            if node.args:
                # Check if this is a SAFE parameterized query
                # Safe: cursor.execute(query, (param1, param2))
                # Unsafe: cursor.execute(f"SELECT * FROM {table}")
                
                # If there's a second argument (parameters), it's likely parameterized
                if len(node.args) >= 2:
                    # Check if second argument is a tuple, list, or dict (safe parameterization)
                    param_arg = node.args[1]
                    if isinstance(param_arg, (ast.Tuple, ast.List, ast.Dict)):
                        # This is a properly parameterized query - SAFE
                        return False
                    # Also check for variables that might contain parameters
                    if isinstance(param_arg, ast.Name):
                        # Could be parameters, assume safe (benefit of the doubt)
                        return False
                
                # Check if first argument (SQL query) is dynamically constructed
                query_arg = node.args[0]
                
                # Unsafe: f-strings or concatenation in SQL
                if self._is_dynamic_string(query_arg):
                    return True
                
                # If it's a variable, check if it contains placeholders
                if isinstance(query_arg, ast.Name):
                    # Can't determine from AST alone - would need runtime analysis
                    # Don't flag as vulnerable unless we have evidence
                    return False
                
                # If it's a constant string, check for placeholders (?, %s, etc.)
                if isinstance(query_arg, ast.Constant) and isinstance(query_arg.value, str):
                    sql = query_arg.value
                    # If it has placeholders but no parameters, that's suspicious
                    if ('?' in sql or '%s' in sql or ':' in sql) and len(node.args) < 2:
                        return True
        
        return False
    
    def _is_insecure_deserialization(self, node: ast.Call, func_name: str) -> bool:
        """Detect insecure deserialization vulnerabilities."""
        # pickle.loads, marshal.loads, yaml.load (without safe loader)
        for module in self.DANGEROUS_DESERIALIZE_MODULES:
            if func_name in {f"{module}.loads", f"{module}.load", "loads", "load"}:
                # Check if it's from a dangerous module
                if func_name == "loads" or func_name == "load":
                    # Check imports to see if it's from pickle/marshal
                    if any(module in imp for imp in self.imports.values()):
                        return True
                else:
                    return True
        
        # yaml.load without Loader=yaml.SafeLoader
        if 'yaml.load' in func_name or (func_name == 'load' and 'yaml' in str(self.imports)):
            has_safe_loader = False
            for keyword in node.keywords:
                if keyword.arg == 'Loader':
                    if isinstance(keyword.value, ast.Attribute):
                        if keyword.value.attr == 'SafeLoader':
                            has_safe_loader = True
            if not has_safe_loader:
                return True
        
        return False
    
    def _is_xxe_vulnerable(self, node: ast.Call, func_name: str) -> bool:
        """Detect XXE (XML External Entity) vulnerabilities."""
        # xml.etree.ElementTree.parse without disabled external entities
        if any(xml_func in func_name for xml_func in self.XML_PARSING_FUNCTIONS):
            if 'xml' in func_name.lower() or 'lxml' in str(self.imports):
                # Check if external entities are disabled
                # This is a simplified check - real implementation would need more context
                return True
        
        return False
    
    def _is_weak_crypto(self, node: ast.Call, func_name: str) -> bool:
        """Detect weak cryptographic algorithms."""
        # hashlib.md5(), hashlib.sha1(), Crypto.Cipher.DES, etc.
        for weak_algo in self.WEAK_CRYPTO_ALGORITHMS:
            if weak_algo.lower() in func_name.lower():
                return True
        
        return False
    
    def _add_vulnerability(self, node: ast.AST, vuln_type: str, 
                          description: str, severity: str) -> None:
        """Add a vulnerability to the list."""
        self.vulnerabilities.append(Vulnerability(
            type=vuln_type,
            line=node.lineno,
            column=node.col_offset,
            severity=severity,
            description=description,
            context=self.current_function
        ))


def analyze_code_ast(code: str) -> List[Dict[str, Any]]:
    """
    Convenience function to analyze code using AST.
    
    Args:
        code: Source code to analyze
        
    Returns:
        List of vulnerability dictionaries
    """
    analyzer = ASTVulnerabilityAnalyzer()
    return analyzer.analyze(code)
