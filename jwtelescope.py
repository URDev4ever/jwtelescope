#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import base64
import argparse
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import re

class Colors:
    """Class for handling terminal colors"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ORANGE = '\033[38;5;214m'
    MAGENTA = '\033[35m'
    WHITE = '\033[37m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class RiskScore:
    """Risk scoring constants"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    
    @staticmethod
    def get_color(score: str) -> str:
        """Get color for risk score"""
        if score == RiskScore.HIGH:
            return Colors.RED
        elif score == RiskScore.MEDIUM:
            return Colors.YELLOW
        else:
            return Colors.GREEN

class JWTelescope:
    """CLI tool for JWT token analysis and decoding"""
    
    def __init__(self):
        # Build banner piece by piece to handle all quotes and triple quotes (took me longer than expected lol)
        self.banner = Colors.ORANGE + """
             ______
          ,'"       "-._
        ,'              "-._ _._
        ;              __,-'/   |
       ;|           ,-' _,'"'._,.
       |:            _,'      |\\ `.
       : \\       _,-'         | \\  `.
        \\ \\   ,-'             |  \\   \\
         \\ '.         .-.     |       \\
          \\  \\         "      |        :
           `. `.              |        |
             `. "-._          |        ;
             / |`._ `-._      L       /
            /  | \\ `._   "-.___    _,'
           /   |  \\_.-"-.___   """ + '""""' + """     _____  __      __  ______        ___
           \\   :            /""" + '"""' + """       /\\___ \\/\\ \\  __/\\ \\/\\__  _\\      /\\_ \\
            `._\\_       __.'_          \\/__/\\ \\ \\ \\/\\ \\ \\ \\/_/\\ \\/    __\\//\\ \\      __    ____    ___    ___   _____      __
       __,--''_ ' "--'''' \\_  `-._        _\\ \\ \\ \\ \\ \\ \\ \\ \\ \\ \\ \\  /'__`\\\\ \\ \\   /'__`\\ /',__\\  /'___\\ / __`\\/\\ '__`\\  /'__`\\
 __,--'     .' /_  |   __. `-._   `-._   /\\ \\_\\ \\ \\ \\_/ \\_\\ \\ \\ \\ \\/\\  __/ \\_\\ \\_/\\  __//\\__, `\\/\\ \\__//\\ \\L\\ \\ \\ \\L\\ \\/\\  __/
<            `.  `-.-''  __,-'     _,-'  \\ \\____/\\ `\\___x___/  \\ \\_\\ \\____\\/\\____\\ \\____\\/\\____/\\ \\____\\ \\____/\\ \\ ,__/\\ \\____\\
 `.            `.   _,-'"      _,-'       \\/___/  '\\/__//__/    \\/_/\\/____/\\/____/\\/____/\\/___/  \\/____/\\/___/  \\ \\ \\/  \\/____/
   `.            ''"       _,-'                               """ + Colors.MAGENTA + """By URDev | v1.4""" + Colors.ORANGE + """                                    \\ \\_\\
     `.                _,-'                                                                                       \\/_/
       `.          _,-'
         `.   __,'"
           `'"
""" + Colors.ENDC
    
    def print_banner(self):
        """Print the tool banner"""
        print(self.banner)
    
    def decode_jwt_part(self, part: str) -> Dict[str, Any]:
        """
        Decode a JWT part (header or payload)
        
        Args:
            part: Base64url encoded string
            
        Returns:
            Dictionary with decoded data
        """
        # Add padding if needed
        missing_padding = len(part) % 4
        if missing_padding:
            part += '=' * (4 - missing_padding)
        
        try:
            decoded_bytes = base64.urlsafe_b64decode(part)
            decoded_str = decoded_bytes.decode('utf-8')
            return json.loads(decoded_str)
        except Exception as e:
            return {"error": f"Could not decode: {str(e)}", "raw": part}
    
    def format_timestamp_value(self, key: str, value: Any) -> Tuple[str, str]:
        """
        Format timestamp values with date conversion and status
        
        Args:
            key: The claim key (exp, iat, nbf)
            value: The timestamp value
            
        Returns:
            Tuple of (formatted_string, status)
        """
        if isinstance(value, (int, float)):
            try:
                dt = datetime.fromtimestamp(value)
                date_str = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                current_time = datetime.now().timestamp()
                
                if key == 'exp':
                    status = "❌ EXPIRED" if value < current_time else "✅ VALID"
                    return f"{Colors.GREEN}{value}{Colors.ENDC} {Colors.CYAN}({date_str}) {status}{Colors.ENDC}", status
                elif key == 'nbf':
                    status = "✅ ACTIVE" if value <= current_time else "⏳ NOT YET VALID"
                    return f"{Colors.GREEN}{value}{Colors.ENDC} {Colors.CYAN}({date_str}) {status}{Colors.ENDC}", status
                else:  # iat or other timestamps
                    return f"{Colors.GREEN}{value}{Colors.ENDC} {Colors.CYAN}({date_str}){Colors.ENDC}", "N/A"
            except:
                return f"{Colors.GREEN}{value}{Colors.ENDC}", "N/A"
        elif isinstance(value, str) and value.isdigit() and len(value) == 10:
            try:
                timestamp = int(value)
                dt = datetime.fromtimestamp(timestamp)
                date_str = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                return f"{Colors.GREEN}\"{value}\"{Colors.ENDC} {Colors.CYAN}({date_str}){Colors.ENDC}", "N/A"
            except:
                return f"{Colors.GREEN}\"{value}\"{Colors.ENDC}", "N/A"
        elif isinstance(value, str):
            # Detect ISO format dates
            date_pattern = r'\d{4}-\d{2}-\d{2}'
            if re.match(date_pattern, value):
                return f"{Colors.GREEN}\"{value}\"{Colors.ENDC} {Colors.CYAN}(Date){Colors.ENDC}", "N/A"
            
            return f"{Colors.GREEN}\"{value}\"{Colors.ENDC}", "N/A"
        else:
            return f"{Colors.GREEN}{value}{Colors.ENDC}", "N/A"
    
    def format_expiration_time(self, exp_time: float) -> str:
        """
        Format expiration time in human readable format
        
        Args:
            exp_time: Expiration timestamp
            
        Returns:
            Human readable time difference
        """
        current_time = datetime.now().timestamp()
        time_diff = current_time - exp_time
        
        if time_diff < 60:  # Less than a minute
            return f"{int(time_diff)} second(s) ago"
        elif time_diff < 3600:  # Less than an hour
            minutes = int(time_diff / 60)
            seconds = int(time_diff % 60)
            return f"{minutes} minute(s) {seconds} second(s) ago"
        elif time_diff < 86400:  # Less than a day
            hours = int(time_diff / 3600)
            minutes = int((time_diff % 3600) / 60)
            return f"{hours} hour(s) {minutes} minute(s) ago"
        elif time_diff < 31536000:  # Less than a year
            days = int(time_diff / 86400)
            hours = int((time_diff % 86400) / 3600)
            return f"{days} day(s) {hours} hour(s) ago"
        else:  # More than a year
            years = int(time_diff / 31536000)
            days = int((time_diff % 31536000) / 86400)
            return f"{years} year(s) {days} day(s) ago"
    
    def format_json_output(self, data: Dict[str, Any], title: str, color: str, raw_mode: bool = False) -> str:
        """
        Format a dictionary as colored JSON
        
        Args:
            data: Dictionary to format
            title: Section title
            color: Color for the title
            raw_mode: If True, output plain JSON without colors
            
        Returns:
            Formatted string
        """
        if raw_mode:
            return f"\n{title}:\n{json.dumps(data, indent=2)}\n"
        
        output = f"\n{color}{Colors.BOLD}{title}:{Colors.ENDC}\n"
        
        def format_value(value, indent=0, current_key=None):
            """Recursive function to format values with colors"""
            indent_str = "  " * indent
            
            if isinstance(value, dict):
                formatted = "{\n"
                keys = list(value.keys())
                for i, k in enumerate(keys):
                    v = value[k]
                    formatted += f"{indent_str}  {Colors.YELLOW}\"{k}\"{Colors.ENDC}: "
                    formatted += format_value(v, indent + 1, k)
                    if i != len(keys) - 1:
                        formatted += ","
                    formatted += "\n"
                formatted += f"{indent_str}}}"
                return formatted
            
            elif isinstance(value, list):
                formatted = f"{Colors.MAGENTA}[\n"
                for i, item in enumerate(value):
                    formatted += f"{indent_str}  "
                    formatted += format_value(item, indent + 1, current_key)
                    if i != len(value) - 1:
                        formatted += ","
                    formatted += "\n"
                formatted += f"{indent_str}{Colors.MAGENTA}]{Colors.ENDC}"
                return formatted
            
            elif isinstance(value, str):
                # Special handling for timestamp keys
                if current_key in ['exp', 'iat', 'nbf']:
                    formatted_value, _ = self.format_timestamp_value(current_key, value)
                    return formatted_value
                
                return f"{Colors.GREEN}\"{value}\"{Colors.ENDC}"
            
            elif isinstance(value, bool):
                return f"{Colors.CYAN}{str(value).lower()}{Colors.ENDC}"
            
            elif value is None:
                return f"{Colors.RED}null{Colors.ENDC}"
            
            elif isinstance(value, (int, float)):
                # Special handling for timestamp keys
                if current_key in ['exp', 'iat', 'nbf']:
                    formatted_value, _ = self.format_timestamp_value(current_key, value)
                    return formatted_value
                
                return f"{Colors.BLUE}{value}{Colors.ENDC}"
            
            else:
                return str(value)
        
        try:
            output += format_value(data)
        except Exception as e:
            output += f"{Colors.RED}Error formatting JSON: {str(e)}{Colors.ENDC}"
        
        return output
    
    def analyze_jwt_structure(self, jwt_parts: list):
        """
        Analyze JWT structure and show additional information
        
        Args:
            jwt_parts: List of JWT parts
        """
        print(f"\n{Colors.CYAN}{Colors.BOLD}JWT Information:{Colors.ENDC}")
        print(f"{Colors.YELLOW}• Token parts:{Colors.ENDC} {len(jwt_parts)}")
        print(f"{Colors.YELLOW}• Length:{Colors.ENDC} {sum(len(part) for part in jwt_parts) + 2} characters")
        
        if len(jwt_parts) >= 2:
            header = self.decode_jwt_part(jwt_parts[0])
            if "alg" in header:
                print(f"{Colors.YELLOW}• Algorithm:{Colors.ENDC} {Colors.BLUE}{header['alg']}{Colors.ENDC}")
            
            if "kid" in header:
                print(f"{Colors.YELLOW}• Key ID:{Colors.ENDC} {Colors.GREEN}{header['kid']}{Colors.ENDC}")
    
    def extract_common_claims(self, payload: Dict[str, Any]):
        """
        Extract and display common claims from payload with proper formatting
        
        Args:
            payload: JWT payload
        """
        common_claims = {
            'iss': 'Issuer',
            'sub': 'Subject',
            'aud': 'Audience',
            'exp': 'Expiration Time',
            'nbf': 'Not Before',
            'iat': 'Issued At',
            'jti': 'JWT ID'
        }
        
        found_claims = []
        for claim, description in common_claims.items():
            if claim in payload:
                value = payload[claim]
                if claim in ['exp', 'iat', 'nbf']:
                    formatted_value, status = self.format_timestamp_value(claim, value)
                    # Remove duplicate status from formatted value for clean display
                    # The formatted value already contains the status at the end
                    found_claims.append((description, formatted_value, status))
                else:
                    found_claims.append((description, value, None))
        
        if found_claims:
            print(f"\n{Colors.CYAN}{Colors.BOLD}Common claims found:{Colors.ENDC}")
            for desc, formatted_value, status in found_claims:
                if status and status != "N/A":
                    # The formatted_value already contains the status, so just print it
                    print(f"  {Colors.YELLOW}{desc:<20}{Colors.ENDC}: {formatted_value}")
                else:
                    print(f"  {Colors.YELLOW}{desc:<20}{Colors.ENDC}: {Colors.GREEN}{formatted_value}{Colors.ENDC}")
    
    def calculate_risk_score(self, header: Dict[str, Any], payload: Dict[str, Any], warnings: List[Tuple[str, str]]) -> Tuple[str, List[Tuple[str, str]]]:
        """
        Calculate risk score based on security issues
        
        Args:
            header: JWT header
            payload: JWT payload
            warnings: List of warnings found
            
        Returns:
            Tuple of (risk_score, enhanced_warnings)
        """
        score = 0
        enhanced_warnings = []
        
        # Critical issues (3 points each)
        if header.get('alg') == 'none' or header.get('alg') == 'None':
            score += 3
            enhanced_warnings.append(("🔓 Algorithm 'none' detected", "Critical: JWT none algorithm vulnerability - token can be forged"))
        
        # High severity issues (2 points each)
        if 'kid' in header:
            kid = header['kid']
            traversal_patterns = ['../', '/etc/', '/proc/', '/var/', '..\\', '%00', '\\x00']
            if any(pattern in kid for pattern in traversal_patterns):
                score += 2
                enhanced_warnings.append(("🧱 Path traversal in 'kid'", f"High: kid: {kid} - Possible key injection/SSRF"))
        
        # Check for expired token
        if 'exp' in payload:
            exp_time = payload['exp']
            if isinstance(exp_time, (int, float)):
                current_time = datetime.now().timestamp()
                if exp_time < current_time:
                    score += 2
                    time_diff_str = self.format_expiration_time(exp_time)
                    enhanced_warnings.append(("⏰ Expired token", f"High: Token expired {time_diff_str}"))
        
        # Missing expiration
        if 'exp' not in payload:
            score += 2
            enhanced_warnings.append(("🔍 No expiration (exp)", "High: Long-lived token - no expiration set"))
        
        # Suspicious expiration (too far in future)
        if 'exp' in payload and isinstance(payload['exp'], (int, float)):
            exp_time = payload['exp']
            current_time = datetime.now().timestamp()
            if exp_time - current_time > 31536000 * 10:  # 10 years
                score += 2
                enhanced_warnings.append(("⏳ Expiration too far", "High: Token expires in >10 years"))
        
        # Weak audience
        if 'aud' in payload:
            aud = payload['aud']
            weak_audiences = ['*', 'null', 'any', 'all', 'public', 'default']
            if isinstance(aud, str) and aud in weak_audiences:
                score += 1
                enhanced_warnings.append(("🎯 Weak audience", f"Medium: aud: '{aud}' - too generic"))
            elif isinstance(aud, list) and any(a in weak_audiences for a in aud):
                score += 1
                enhanced_warnings.append(("🎯 Weak audience in array", "Medium: Audience array contains generic values"))
        
        # Algorithm confusion risk
        symmetric_algorithms = ['HS256', 'HS384', 'HS512']
        if header.get('alg') in symmetric_algorithms:
            score += 1
            enhanced_warnings.append(("🔄 Symmetric algorithm", 
                                    f"Medium: {header['alg']} - HS/RS confusion possible if public key reused"))
        
        # Dangerous custom claims
        dangerous_claims = ['admin', 'isadmin', 'role', 'roles', 'scope', 'scopes', 
                          'permission', 'permissions', 'superuser', 'root', 'privileged']
        for claim in dangerous_claims:
            if claim in payload:
                score += 1
                enhanced_warnings.append((f"🧪 Custom claim '{claim}'", 
                                        f"Medium: Potential privilege escalation vector - value: {payload[claim]}"))
                break
        
        # Missing nbf
        if 'nbf' not in payload:
            score += 0.5
            enhanced_warnings.append(("🔓 Missing 'nbf' claim", "Low: Token can be used immediately after issuance"))
        
        # Predictable kid pattern
        if 'kid' in header:
            kid = header['kid']
            # Check for UUID patterns or incremental IDs
            uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            if re.match(uuid_pattern, kid, re.IGNORECASE):
                # Check if UUID is sequential/predictable
                if '00000000' in kid or '11111111' in kid or '12345678' in kid:
                    score += 1
                    enhanced_warnings.append(("🧱 Predictable KID UUID", f"Medium: kid: {kid} - potentially predictable"))
        
        # External jku/x5u
        suspicious_urls = ['jku', 'x5u']
        for url_field in suspicious_urls:
            if url_field in header:
                url = header[url_field]
                if any(domain in url.lower() for domain in ['localhost', '127.0.0.1', '0.0.0.0', 'internal', 'test']):
                    score += 2
                    enhanced_warnings.append((f"🌐 Suspicious {url_field} URL", 
                                            f"High: {url_field}: {url} - Points to internal/controllable domain"))
                elif not url.startswith(('https://', 'http://')):
                    score += 1
                    enhanced_warnings.append((f"🌐 Non-HTTP {url_field}", 
                                            f"Medium: {url_field}: {url} - Non-standard URL scheme"))
        
        # Missing typ
        if 'typ' not in header:
            score += 0.5
            enhanced_warnings.append(("📛 Missing 'typ' claim", "Low: Standard JWT should include typ: 'JWT'"))
        elif header.get('typ') != 'JWT':
            score += 0.5
            enhanced_warnings.append(("📛 Non-standard 'typ' value", f"Low: typ: {header['typ']} - Expected 'JWT'"))
        
        # Determine risk level
        if score >= 5:
            risk_score = RiskScore.HIGH
        elif score >= 2:
            risk_score = RiskScore.MEDIUM
        else:
            risk_score = RiskScore.LOW
        
        return risk_score, enhanced_warnings
    
    def check_security_issues(self, header: Dict[str, Any], payload: Dict[str, Any], only_warnings: bool = False) -> List[Tuple[str, str]]:
        """
        Check for potential security issues in the JWT
        
        Args:
            header: JWT header
            payload: JWT payload
            only_warnings: If True, only return warnings without printing
            
        Returns:
            List of warning tuples
        """
        risk_score, warnings = self.calculate_risk_score(header, payload, [])
        
        if not only_warnings:
            # Show risk score
            risk_color = RiskScore.get_color(risk_score)
            print(f"\n{Colors.CYAN}{Colors.BOLD}Risk Assessment:{Colors.ENDC}")
            print(f"  {Colors.YELLOW}Risk Score:{Colors.ENDC} {risk_color}{risk_score}{Colors.ENDC}")
            
            if warnings:
                print(f"\n{Colors.RED}{Colors.BOLD}⚠  Security findings:{Colors.ENDC}")
                for issue, description in warnings:
                    severity = description.split(":")[0]
                    if severity == "Critical":
                        color = Colors.RED + Colors.BOLD
                    elif severity == "High":
                        color = Colors.RED
                    elif severity == "Medium":
                        color = Colors.YELLOW
                    else:
                        color = Colors.CYAN
                    
                    print(f"  {color}• {issue}:{Colors.ENDC} {description}")
        
        return warnings
    
    def generate_json_output(self, header: Dict[str, Any], payload: Dict[str, Any], 
                           jwt_parts: list, warnings: List[Tuple[str, str]], 
                           risk_score: str) -> Dict[str, Any]:
        """
        Generate structured JSON output
        
        Args:
            header: JWT header
            payload: JWT payload
            jwt_parts: JWT parts
            warnings: List of warnings
            risk_score: Risk score
            
        Returns:
            Structured JSON dictionary
        """
        # Calculate token age if iat exists
        token_age = None
        if 'iat' in payload and isinstance(payload['iat'], (int, float)):
            current_time = datetime.now().timestamp()
            token_age = int(current_time - payload['iat'])
        
        # Get expiration status
        expiration_status = None
        if 'exp' in payload and isinstance(payload['exp'], (int, float)):
            current_time = datetime.now().timestamp()
            expiration_status = "expired" if payload['exp'] < current_time else "valid"
        
        return {
            "metadata": {
                "tool": "JWTelescope",
                "version": "1.4",
                "analysis_timestamp": datetime.now().isoformat()
            },
            "token_info": {
                "parts": len(jwt_parts),
                "total_length": sum(len(part) for part in jwt_parts) + 2,
                "algorithm": header.get('alg'),
                "key_id": header.get('kid'),
                "type": header.get('typ'),
                "has_expiration": 'exp' in payload,
                "has_not_before": 'nbf' in payload,
                "token_age_seconds": token_age,
                "expiration_status": expiration_status
            },
            "header": header,
            "payload": payload,
            "security_analysis": {
                "risk_score": risk_score,
                "findings": [
                    {
                        "issue": issue,
                        "description": desc,
                        "severity": desc.split(":")[0].lower() if ":" in desc else "info"
                    }
                    for issue, desc in warnings
                ],
                "findings_count": len(warnings)
            },
            "common_claims": {
                "issuer": payload.get('iss'),
                "subject": payload.get('sub'),
                "audience": payload.get('aud'),
                "issued_at": payload.get('iat'),
                "expiration": payload.get('exp'),
                "not_before": payload.get('nbf'),
                "jwt_id": payload.get('jti')
            }
        }
    
    def read_jwt(self, jwt_token: str, raw_mode: bool = False, only_warnings: bool = False, 
                 json_output: bool = False, show_score: bool = False):
        """
        Read and decode a JWT token
        
        Args:
            jwt_token: JWT token to analyze
            raw_mode: If True, output plain JSON without formatting
            only_warnings: If True, only show security warnings
            json_output: If True, output structured JSON
            show_score: If True, show risk score
        """
        try:
            # Split the JWT into its parts
            jwt_parts = jwt_token.split('.')
            
            if len(jwt_parts) < 2:
                print(f"{Colors.RED}Error: Invalid JWT token. Expected format: header.payload.signature{Colors.ENDC}")
                return
            
            # Decode header
            header = self.decode_jwt_part(jwt_parts[0])
            
            # Decode payload
            payload = self.decode_jwt_part(jwt_parts[1])
            
            # Calculate risk score
            risk_score, warnings = self.calculate_risk_score(header, payload, [])
            
            # JSON output mode
            if json_output:
                json_data = self.generate_json_output(header, payload, jwt_parts, warnings, risk_score)
                print(json.dumps(json_data, indent=2))
                return
            
            # Only warnings mode
            if only_warnings:
                if warnings:
                    print(f"\n{Colors.RED}{Colors.BOLD}Security findings for token:{Colors.ENDC}")
                    for issue, description in warnings:
                        severity = description.split(":")[0]
                        if severity == "Critical":
                            color = Colors.RED + Colors.BOLD
                        elif severity == "High":
                            color = Colors.RED
                        elif severity == "Medium":
                            color = Colors.YELLOW
                        else:
                            color = Colors.CYAN
                        
                        print(f"  {color}• {issue}:{Colors.ENDC} {description}")
                    
                    # Show risk score if requested
                    if show_score:
                        risk_color = RiskScore.get_color(risk_score)
                        print(f"\n{Colors.CYAN}Overall Risk:{Colors.ENDC} {risk_color}{risk_score}{Colors.ENDC}")
                else:
                    print(f"{Colors.GREEN}No security issues found.{Colors.ENDC}")
                return
            
            # Normal output mode
            if not raw_mode:
                print(f"{Colors.WHITE}{'='*60}{Colors.ENDC}")
                print(f"{Colors.CYAN}{Colors.BOLD}Analyzing JWT token...{Colors.ENDC}")
                print(f"{Colors.WHITE}{'='*60}{Colors.ENDC}")
            
            # Show decoded data
            print(self.format_json_output(header, "Header", Colors.BLUE, raw_mode))
            print(self.format_json_output(payload, "Payload", Colors.GREEN, raw_mode))
            
            # Show signature information
            if len(jwt_parts) > 2:
                signature = jwt_parts[2]
                if raw_mode:
                    print(f"\nSignature:\n{signature}")
                else:
                    print(f"\n{Colors.RED}{Colors.BOLD}Signature:{Colors.ENDC}")
                    print(f"{Colors.WHITE}{signature[:50]}...{Colors.ENDC}")
                    print(f"{Colors.YELLOW}• Length:{Colors.ENDC} {len(signature)} characters")
                    print(f"{Colors.YELLOW}• Format:{Colors.ENDC} Base64URL")
            
            # Additional analysis (skip in raw mode)
            if not raw_mode:
                self.analyze_jwt_structure(jwt_parts)
                self.extract_common_claims(payload)
                self.check_security_issues(header, payload, only_warnings)
                
                # Show score if requested
                if show_score:
                    risk_color = RiskScore.get_color(risk_score)
                    print(f"\n{Colors.CYAN}{Colors.BOLD}Risk Score:{Colors.ENDC} {risk_color}{risk_score}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.RED}Error processing JWT: {str(e)}{Colors.ENDC}")
    
    def run(self):
        """Main method to run the tool"""
        parser = argparse.ArgumentParser(
            description='JWTelescope - Advanced JWT token analysis and decoding tool',
            add_help=False,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s -r "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  %(prog)s -f token.jwt --raw
  %(prog)s --no-banner --only-warnings -r "$(pbpaste)"
  %(prog)s --json -f auth_token.txt > report.json
  %(prog)s --score --only-warnings -r "JWT_TOKEN"
  echo "JWT_TOKEN" | %(prog)s --stdin
"""
        )
        
        parser.add_argument(
            '-h', '--help',
            action='help',
            default=argparse.SUPPRESS,
            help='Show this help message and exit'
        )
        
        parser.add_argument(
            '-nb', '--no-banner',
            action='store_true',
            help='Do not show banner at startup'
        )
        
        parser.add_argument(
            '-r', '--read',
            metavar='JWT',
            type=str,
            help='Read and decode a JWT token'
        )
        
        parser.add_argument(
            '-f', '--file',
            metavar='FILE',
            type=str,
            help='Read JWT from a file'
        )
        
        parser.add_argument(
            '--stdin',
            action='store_true',
            help='Read JWT from standard input'
        )
        
        parser.add_argument(
            '--raw',
            action='store_true',
            help='Output raw JSON without colors or analysis (useful for piping)'
        )
        
        parser.add_argument(
            '--only-warnings',
            action='store_true',
            help='Only show security warnings (useful for quick triage)'
        )
        
        parser.add_argument(
            '--json',
            action='store_true',
            help='Output structured JSON analysis (for reports)'
        )
        
        parser.add_argument(
            '--score',
            action='store_true',
            help='Show risk score assessment'
        )
        
        parser.add_argument(
            '-v', '--version',
            action='version',
            version='JWTelescope v1.4 - By URDev',
            help='Show version information'
        )
        
        # If no arguments provided, show help with banner
        if len(sys.argv) == 1:
            self.print_banner()
            parser.print_help()
            sys.exit(1)
        
        args = parser.parse_args()
        
        # Show banner unless --no-banner is specified
        if not args.no_banner and not args.json and not args.raw:
            self.print_banner()
        
        # Get JWT token
        jwt_token = None
        
        if args.stdin:
            # Read from stdin
            jwt_token = sys.stdin.read().strip()
        elif args.read:
            jwt_token = args.read
        elif args.file:
            try:
                with open(args.file, 'r') as f:
                    jwt_token = f.read().strip()
            except FileNotFoundError:
                print(f"{Colors.RED}Error: File '{args.file}' not found{Colors.ENDC}")
                sys.exit(1)
            except Exception as e:
                print(f"{Colors.RED}Error reading file: {str(e)}{Colors.ENDC}")
                sys.exit(1)
        
        if jwt_token:
            # Process JWT
            self.read_jwt(jwt_token, args.raw, args.only_warnings, args.json, args.score or args.only_warnings)
        else:
            print(f"{Colors.YELLOW}No JWT token provided. Use -r, -f, or --stdin to provide a token.{Colors.ENDC}")

def main():
    """Main function"""
    try:
        tool = JWTelescope()
        tool.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Unexpected error: {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
