//! Filter DSL Parser
//!
//! Supports expressions like:
//!   tcp
//!   udp && port 53
//!   ip == 192.168.1.1
//!   tcp && port 443 && ip != 10.0.0.1
//!   http || dns
//!   port 80..443
//!   len > 1000
//!   direction == in

use std::fmt;

/// Token types for the filter language
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Protocols
    Protocol(String),
    // Operators
    And,
    Or,
    Not,
    Eq,
    NotEq,
    Gt,
    Lt,
    GtEq,
    LtEq,
    // Fields
    Field(String),
    // Values
    StringValue(String),
    NumberValue(u64),
    // Range
    Range(u64, u64),
    // Grouping
    LParen,
    RParen,
}

/// AST node for filter expressions
#[derive(Debug, Clone)]
pub enum FilterExpr {
    /// Match a protocol: tcp, udp, icmp, arp, http, dns, tls, ssh
    Protocol(String),
    /// Compare a field: ip == x, port == x, len > x
    Comparison {
        field: String,
        op: CompareOp,
        value: FilterValue,
    },
    /// Port range: port 80..443
    PortRange { start: u16, end: u16 },
    /// Logical AND
    And(Box<FilterExpr>, Box<FilterExpr>),
    /// Logical OR
    Or(Box<FilterExpr>, Box<FilterExpr>),
    /// Logical NOT
    Not(Box<FilterExpr>),
    /// Contains substring: contains "google"
    Contains(String),
    /// Always true
    True,
}

#[derive(Debug, Clone)]
pub enum CompareOp {
    Eq,
    NotEq,
    Gt,
    Lt,
    GtEq,
    LtEq,
}

#[derive(Debug, Clone)]
pub enum FilterValue {
    Str(String),
    Num(u64),
}

impl fmt::Display for FilterExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterExpr::Protocol(p) => write!(f, "{}", p),
            FilterExpr::Comparison { field, op, value } => {
                let op_str = match op {
                    CompareOp::Eq => "==",
                    CompareOp::NotEq => "!=",
                    CompareOp::Gt => ">",
                    CompareOp::Lt => "<",
                    CompareOp::GtEq => ">=",
                    CompareOp::LtEq => "<=",
                };
                match value {
                    FilterValue::Str(s) => write!(f, "{} {} {}", field, op_str, s),
                    FilterValue::Num(n) => write!(f, "{} {} {}", field, op_str, n),
                }
            }
            FilterExpr::PortRange { start, end } => write!(f, "port {}..{}", start, end),
            FilterExpr::And(a, b) => write!(f, "({} && {})", a, b),
            FilterExpr::Or(a, b) => write!(f, "({} || {})", a, b),
            FilterExpr::Not(e) => write!(f, "!{}", e),
            FilterExpr::Contains(s) => write!(f, "contains \"{}\"", s),
            FilterExpr::True => write!(f, "*"),
        }
    }
}

/// Parse a filter string into a FilterExpr
pub fn parse_filter(input: &str) -> Result<FilterExpr, String> {
    let input = input.trim();
    if input.is_empty() || input == "*" {
        return Ok(FilterExpr::True);
    }

    let tokens = tokenize(input)?;
    parse_or(&tokens, &mut 0)
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        // Skip whitespace
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }

        // Parentheses
        if chars[i] == '(' {
            tokens.push(Token::LParen);
            i += 1;
            continue;
        }
        if chars[i] == ')' {
            tokens.push(Token::RParen);
            i += 1;
            continue;
        }

        // Operators
        if chars[i] == '&' && i + 1 < chars.len() && chars[i + 1] == '&' {
            tokens.push(Token::And);
            i += 2;
            continue;
        }
        if chars[i] == '|' && i + 1 < chars.len() && chars[i + 1] == '|' {
            tokens.push(Token::Or);
            i += 2;
            continue;
        }
        if chars[i] == '!' && i + 1 < chars.len() && chars[i + 1] == '=' {
            tokens.push(Token::NotEq);
            i += 2;
            continue;
        }
        if chars[i] == '!' {
            tokens.push(Token::Not);
            i += 1;
            continue;
        }
        if chars[i] == '=' && i + 1 < chars.len() && chars[i + 1] == '=' {
            tokens.push(Token::Eq);
            i += 2;
            continue;
        }
        if chars[i] == '>' && i + 1 < chars.len() && chars[i + 1] == '=' {
            tokens.push(Token::GtEq);
            i += 2;
            continue;
        }
        if chars[i] == '<' && i + 1 < chars.len() && chars[i + 1] == '=' {
            tokens.push(Token::LtEq);
            i += 2;
            continue;
        }
        if chars[i] == '>' {
            tokens.push(Token::Gt);
            i += 1;
            continue;
        }
        if chars[i] == '<' {
            tokens.push(Token::Lt);
            i += 1;
            continue;
        }

        // Quoted string
        if chars[i] == '"' {
            i += 1;
            let start = i;
            while i < chars.len() && chars[i] != '"' {
                i += 1;
            }
            if i >= chars.len() {
                return Err("Unterminated string".to_string());
            }
            let s: String = chars[start..i].iter().collect();
            tokens.push(Token::StringValue(s));
            i += 1;
            continue;
        }

        // Number or range
        if chars[i].is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let num1: u64 = chars[start..i]
                .iter()
                .collect::<String>()
                .parse()
                .map_err(|e| format!("Invalid number: {}", e))?;

            // Check for range (..)
            if i + 1 < chars.len() && chars[i] == '.' && chars[i + 1] == '.' {
                i += 2;
                let start2 = i;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let num2: u64 = chars[start2..i]
                    .iter()
                    .collect::<String>()
                    .parse()
                    .map_err(|e| format!("Invalid range end: {}", e))?;
                tokens.push(Token::Range(num1, num2));
            } else {
                tokens.push(Token::NumberValue(num1));
            }
            continue;
        }

        // Word (protocol, field, keyword)
        if chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.' || chars[i] == ':' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_alphanumeric()
                    || chars[i] == '_'
                    || chars[i] == '.'
                    || chars[i] == ':')
            {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect::<String>().to_lowercase();

            match word.as_str() {
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                "not" => tokens.push(Token::Not),
                "tcp" | "udp" | "icmp" | "icmpv6" | "arp" | "http" | "dns" | "tls"
                | "ssh" | "dhcp" | "ipv4" | "ipv6" | "igmp" | "ftp" | "smtp" | "mqtt" => {
                    tokens.push(Token::Protocol(word));
                }
                "ip" | "src" | "dst" | "port" | "sport" | "dport" | "len" | "length"
                | "direction" | "dir" | "interface" | "iface" | "ttl" | "mac" => {
                    tokens.push(Token::Field(word));
                }
                "contains" => tokens.push(Token::Field("contains".to_string())),
                "in" | "out" | "incoming" | "outgoing" => {
                    tokens.push(Token::StringValue(word));
                }
                _ => {
                    // Could be an IP address or hostname
                    tokens.push(Token::StringValue(word));
                }
            }
            continue;
        }

        return Err(format!("Unexpected character: '{}'", chars[i]));
    }

    Ok(tokens)
}

fn parse_or(tokens: &[Token], pos: &mut usize) -> Result<FilterExpr, String> {
    let mut left = parse_and(tokens, pos)?;

    while *pos < tokens.len() && tokens[*pos] == Token::Or {
        *pos += 1;
        let right = parse_and(tokens, pos)?;
        left = FilterExpr::Or(Box::new(left), Box::new(right));
    }

    Ok(left)
}

fn parse_and(tokens: &[Token], pos: &mut usize) -> Result<FilterExpr, String> {
    let mut left = parse_unary(tokens, pos)?;

    while *pos < tokens.len() && tokens[*pos] == Token::And {
        *pos += 1;
        let right = parse_unary(tokens, pos)?;
        left = FilterExpr::And(Box::new(left), Box::new(right));
    }

    Ok(left)
}

fn parse_unary(tokens: &[Token], pos: &mut usize) -> Result<FilterExpr, String> {
    if *pos < tokens.len() && tokens[*pos] == Token::Not {
        *pos += 1;
        let expr = parse_primary(tokens, pos)?;
        return Ok(FilterExpr::Not(Box::new(expr)));
    }
    parse_primary(tokens, pos)
}

fn parse_primary(tokens: &[Token], pos: &mut usize) -> Result<FilterExpr, String> {
    if *pos >= tokens.len() {
        return Err("Unexpected end of filter expression".to_string());
    }

    match &tokens[*pos] {
        Token::LParen => {
            *pos += 1;
            let expr = parse_or(tokens, pos)?;
            if *pos >= tokens.len() || tokens[*pos] != Token::RParen {
                return Err("Missing closing parenthesis".to_string());
            }
            *pos += 1;
            Ok(expr)
        }
        Token::Protocol(proto) => {
            let proto = proto.clone();
            *pos += 1;
            Ok(FilterExpr::Protocol(proto))
        }
        Token::Field(field) => {
            let field = field.clone();
            *pos += 1;

            // "contains" keyword
            if field == "contains" {
                if *pos < tokens.len() {
                    if let Token::StringValue(s) = &tokens[*pos] {
                        let s = s.clone();
                        *pos += 1;
                        return Ok(FilterExpr::Contains(s));
                    }
                }
                return Err("Expected string after 'contains'".to_string());
            }

            // Check for comparison operator
            if *pos < tokens.len() {
                let op = match &tokens[*pos] {
                    Token::Eq => Some(CompareOp::Eq),
                    Token::NotEq => Some(CompareOp::NotEq),
                    Token::Gt => Some(CompareOp::Gt),
                    Token::Lt => Some(CompareOp::Lt),
                    Token::GtEq => Some(CompareOp::GtEq),
                    Token::LtEq => Some(CompareOp::LtEq),
                    _ => None,
                };

                if let Some(op) = op {
                    *pos += 1;
                    if *pos >= tokens.len() {
                        return Err(format!("Expected value after operator for field '{}'", field));
                    }
                    let value = match &tokens[*pos] {
                        Token::NumberValue(n) => {
                            let n = *n;
                            *pos += 1;
                            FilterValue::Num(n)
                        }
                        Token::StringValue(s) => {
                            let s = s.clone();
                            *pos += 1;
                            FilterValue::Str(s)
                        }
                        _ => return Err("Expected value".to_string()),
                    };
                    return Ok(FilterExpr::Comparison { field, op, value });
                }

                // Check for range (port 80..443)
                if let Token::Range(start, end) = &tokens[*pos] {
                    let start = *start as u16;
                    let end = *end as u16;
                    *pos += 1;
                    return Ok(FilterExpr::PortRange { start, end });
                }

                // Check for bare number (port 443)
                if let Token::NumberValue(n) = &tokens[*pos] {
                    let n = *n;
                    *pos += 1;
                    return Ok(FilterExpr::Comparison {
                        field,
                        op: CompareOp::Eq,
                        value: FilterValue::Num(n),
                    });
                }

                // Check for bare string (direction in)
                if let Token::StringValue(s) = &tokens[*pos] {
                    let s = s.clone();
                    *pos += 1;
                    return Ok(FilterExpr::Comparison {
                        field,
                        op: CompareOp::Eq,
                        value: FilterValue::Str(s),
                    });
                }
            }

            Err(format!("Expected operator or value after field '{}'", field))
        }
        _ => Err(format!("Unexpected token: {:?}", tokens[*pos])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_protocol() {
        let expr = parse_filter("tcp").unwrap();
        assert!(matches!(expr, FilterExpr::Protocol(p) if p == "tcp"));
    }

    #[test]
    fn test_and_expression() {
        let expr = parse_filter("tcp && port == 443").unwrap();
        assert!(matches!(expr, FilterExpr::And(_, _)));
    }

    #[test]
    fn test_or_expression() {
        let expr = parse_filter("http || dns").unwrap();
        assert!(matches!(expr, FilterExpr::Or(_, _)));
    }

    #[test]
    fn test_port_range() {
        let expr = parse_filter("port 80..443").unwrap();
        assert!(matches!(expr, FilterExpr::PortRange { start: 80, end: 443 }));
    }

    #[test]
    fn test_empty_filter() {
        let expr = parse_filter("").unwrap();
        assert!(matches!(expr, FilterExpr::True));
    }
}