// TODO: Add semantic analysis between parsing and visiting using symbol table
// TODO: Semantic analysis is to make program make sense(type checking)
// TODO: Add source-to-source code
// TODO: Add variable scope
// TODO: Add procedure and procedure calls
package main

import (
	"bufio"
	"fmt"
	"github.com/spf13/cast"
	"math"
	"os"
	"strings"
)

var _symbolTable = make(map[string]interface{}, 0)

func IsDigit(ch byte) bool         { return '0' <= ch && ch <= '9' }
func IsSpace(ch byte) bool         { return ch == ' ' || ch == '\n' || ch == '\t' }
func IsPlus(ch byte) bool          { return ch == '+' }
func IsMinus(ch byte) bool         { return ch == '-' }
func IsFloatDivision(ch byte) bool { return ch == '/' }
func IsMulti(ch byte) bool         { return ch == '*' }
func IsLparen(ch byte) bool        { return ch == '(' }
func IsRparen(ch byte) bool        { return ch == ')' }
func IsSemicolon(ch byte) bool     { return ch == ';' }
func IsColon(ch byte) bool         { return ch == ':' }
func IsDot(ch byte) bool           { return ch == '.' }
func IsAlpha(ch byte) bool         { return ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z') }
func IsUnderscore(ch byte) bool    { return ch == '_' }
func IsLeftBrace(ch byte) bool     { return ch == '{' }
func IsRightBrace(ch byte) bool    { return ch == '}' }
func IsComma(ch byte) bool         { return ch == ',' }
func IsAlphaOrDigit(ch byte) bool  { return IsAlpha(ch) || IsDigit(ch) }
func Fail(err ...string) {
	if len(err) == 0 {
		panic("syntax error")
	} else {
		panic(err[0])
	}
}

type TokenType int

const (
	TokenTypeUnknown TokenType = iota - 1
	TokenTypeEOF
	TokenTypeKeywordInteger    // 'INTEGER'
	TokenTypePlus              // '+'
	TokenTypeMinus             // '-'
	TokenTypeMulti             // '*'
	TokenTypeLparen            // '('
	TokenTypeRparen            // ')'
	TokenTypeDot               // '.'
	TokenTypeSemi              // ';'
	TokenTypeKeywordBegin      // 'BEGIN'
	TokenTypeKeywordEnd        // 'END'
	TokenTypeIdentifier        // 变量名
	TokenTypeAssign            // ':='
	TokenTypeKeywordIntegerDiv // 'div'
	TokenTypeFloatDiv          // '/'
	TokenTypeKeywordProgram    // 'PROGRAM'
	TokenTypeKeywordVar        // 'var'
	TokenTypeColon             // ':'
	TokenTypeComma             // ','
	TokenTypeKeywordReal       // 'REAL'
	TokenTypeIntegerConst      // '725' etc.
	TokenTypeRealConst         // '123.1' etc
)

var _keywords = map[string]Token{
	"BEGIN":   {Type: TokenTypeKeywordBegin, Value: "BEGIN"},
	"END":     {Type: TokenTypeKeywordEnd, Value: "END"},
	"DIV":     {Type: TokenTypeKeywordIntegerDiv, Value: "DIV"},
	"PROGRAM": {Type: TokenTypeKeywordProgram, Value: "PROGRAM"},
	"VAR":     {Type: TokenTypeKeywordVar, Value: "VAR"},
	"INTEGER": {Type: TokenTypeKeywordInteger, Value: "INTEGER"},
	"REAL":    {Type: TokenTypeKeywordReal, Value: "REAL"},
}

type Token struct {
	Type  TokenType
	Value interface{}
}

type AST_NODE_TYPE int

const (
	AST_NODE_TYPE_BIN_OP AST_NODE_TYPE = iota
	AST_NODE_TYPE_INTEGER_CONST
	AST_NODE_TYPE_UNARY_OP
	AST_NODE_TYPE_COMPOUND
	AST_NODE_TYPE_ASSIGN
	AST_NODE_TYPE_NOOP
	AST_NODE_TYPE_IDENTIFIER
	AST_NODE_TYPE_REAL_CONST
	AST_NODE_TYPE_PROGRAM
	AST_NODE_TYPE_BLOCK
	AST_NODE_TYPE_VAR
	AST_NODE_TYPE_INTEGER_TYPE
	AST_NODE_TYPE_REAL_TYPE
)

func DoSemanticAnalysis(root *ASTNode) error {
	return nil
}

func Interpret(node *ASTNode) float64 {
	if node == nil {
		return 0
	}
	switch node.Type {
	case AST_NODE_TYPE_PROGRAM:
		Interpret(node.Children[1])
	case AST_NODE_TYPE_BLOCK:
		for _, child := range node.Children {
			Interpret(child)
		}
	case AST_NODE_TYPE_VAR:
	case AST_NODE_TYPE_REAL_TYPE, AST_NODE_TYPE_INTEGER_TYPE:
	case AST_NODE_TYPE_COMPOUND:
		for _, child := range node.Children {
			Interpret(child)
		}
	case AST_NODE_TYPE_NOOP: // 空语句
		return 0
	case AST_NODE_TYPE_ASSIGN: // 赋值运算符
		varName := node.Children[0].Token.Value
		_symbolTable[varName.(string)] = Interpret(node.Children[1])
	case AST_NODE_TYPE_IDENTIFIER: // 标识符
		val, ok := _symbolTable[node.Token.Value.(string)].(float64)
		if !ok { // 此检查应当放到语法分析阶段
			Fail("name error")
		}
		return val
	case AST_NODE_TYPE_INTEGER_CONST, AST_NODE_TYPE_REAL_CONST:
		return node.Token.Value.(float64)
	case AST_NODE_TYPE_UNARY_OP:
		if node.Token.Type == TokenTypePlus {
			return +(Interpret(node.Children[0]))
		}
		if node.Token.Type == TokenTypeMinus {
			return -(Interpret(node.Children[0]))
		}
	case AST_NODE_TYPE_BIN_OP:
		left, right := Interpret(node.Children[0]), Interpret(node.Children[1])
		switch node.Token.Type {
		case TokenTypePlus:
			return left + right
		case TokenTypeMinus:
			return left - right
		case TokenTypeMulti:
			return left * right
		case TokenTypeKeywordIntegerDiv:
			return math.Floor(left / right)
		case TokenTypeFloatDiv:
			return left / right
		default:
			return 0
		}
	}
	return 0
}

// ---------Lexer----------
type Lexer struct {
	RawExp       string
	L            int
	Index        int
	CurrentToken Token
}

func (l *Lexer) Eat(tokenType TokenType) {
	if l.CurrentToken.Type == tokenType {
		nextToken, err := l.GetNextToken()
		if err != nil {
			Fail()
		}
		l.CurrentToken = nextToken
	} else {
		Fail()
	}
}

func (l *Lexer) __id() Token {
	id := ""
	for l.Index < len(l.RawExp) {
		if ch := l.RawExp[l.Index]; IsAlphaOrDigit(ch) || IsUnderscore(ch) {
			id += string(ch)
			l.Index++
		} else {
			break
		}
	}
	id = strings.ToUpper(id)
	if tk, ok := _keywords[id]; ok {
		return tk
	}
	return Token{
		Type:  TokenTypeIdentifier,
		Value: id,
	}
}

func (l *Lexer) GetNextToken() (Token, error) {
	if l.Index > len(l.RawExp)-1 {
		return Token{TokenTypeEOF, nil}, nil
	}
	for l.Index < len(l.RawExp) {
		ch := l.RawExp[l.Index]
		switch {
		case IsSpace(ch):
			l.Index++
			continue
		case IsLeftBrace(ch):
			l.SkipComment()
			continue
		case IsAlpha(ch) || IsUnderscore(ch): // 标识符or关键字, div etc.
			return l.__id(), nil
		case IsComma(ch):
			l.Index++
			return Token{TokenTypeComma, ","}, nil
		case IsColon(ch):
			l.Index++
			if ch, err := l.Peek(l.Index); err == nil && ch == '=' {
				l.Index++
				return Token{TokenTypeAssign, ":="}, nil
			}
			return Token{TokenTypeColon, ":"}, nil
		case IsSemicolon(ch):
			l.Index++
			return Token{TokenTypeSemi, ";"}, nil
		case IsDot(ch):
			l.Index++
			return Token{TokenTypeDot, "."}, nil
		case IsDigit(ch):
			ret := ""
			for c := ch; IsDigit(c); c = l.RawExp[l.Index] {
				ret += string(c)
				l.Index++
				if l.Index >= l.L {
					break
				}
			}
			// integer const
			if l.Index >= l.L || l.RawExp[l.Index] != '.' {
				return Token{TokenTypeIntegerConst, cast.ToFloat64(ret)}, nil
			}
			// float const
			ret += "."
			l.Index++
			for IsDigit(l.RawExp[l.Index]) {
				ret += string(l.RawExp[l.Index])
				l.Index++
				if l.Index >= l.L {
					break
				}
			}
			return Token{TokenTypeRealConst, cast.ToFloat64(ret)}, nil
		case IsPlus(ch):
			l.Index++
			return Token{TokenTypePlus, "+"}, nil
		case IsMinus(ch):
			l.Index++
			return Token{TokenTypeMinus, "-"}, nil
		case IsMulti(ch):
			l.Index++
			return Token{TokenTypeMulti, "*"}, nil
		case IsFloatDivision(ch):
			l.Index++
			return Token{TokenTypeFloatDiv, "/"}, nil
		case IsLparen(ch):
			l.Index++
			return Token{TokenTypeLparen, "("}, nil
		case IsRparen(ch):
			l.Index++
			return Token{TokenTypeRparen, ")"}, nil
		default:
			return Token{}, fmt.Errorf("illegal character encountered: %v, in %v", ch, l.Index)
		}
	}
	return Token{TokenTypeEOF, nil}, nil
}

func (l *Lexer) Peek(pos int) (byte, error) {
	if pos >= len(l.RawExp) {
		return 0, fmt.Errorf("peek: end of input")
	}
	return l.RawExp[pos], nil
}

func (l *Lexer) SkipComment() {
	if !l.CanAdvance() {
		return
	}
	if l.RawExp[l.Index] == '{' {
		l.Index++
		for l.CanAdvance() {
			if l.RawExp[l.Index] == '}' {
				l.Index++
				return
			}
			l.Index++
		}
		Fail("syntax error: comment error")
	}
}

func (l *Lexer) CanAdvance() bool {
	return l.Index < l.L
}

/* ---Grammar---
program : PROGRAM variable SEMI block DOT
block : declarations compound_statement
declarations : VAR (variable_declaration SEMI)+ | empty
variable_declaration : ID (COMMA ID)* COLON type_spec
type_spec : INTEGER | REAL
compound_statement : BEGIN statement_list END
statement_list : statement | statement SEMI statement_list
statement : compound_statement | assignment_statement | empty
assignment_statement : variable ASSIGN expr
empty :
expr : term ((PLUS | MINUS) term)*
term : factor ((MUL | INTEGER_DIV | FLOAT_DIV) factor)*
factor : PLUS factor | MINUS factor | INTEGER_CONST | REAL_CONST | LPAREN expr RPAREN | variable
variable: ID
*/

// -------AST---------
type ASTNode struct {
	Type     AST_NODE_TYPE // for visiting
	Children []*ASTNode
	Token    Token
	// Left, Right *ASTNode
}

// -----parser-------
type Parser struct {
	lex Lexer
}

// program : PROGRAM variable SEMI block DOT
func (p *Parser) Program() *ASTNode {
	p.lex.Eat(TokenTypeKeywordProgram)

	varNode := p.VariableStmt()
	p.lex.Eat(TokenTypeSemi)

	blockNode := p.Block()
	p.lex.Eat(TokenTypeDot)

	return &ASTNode{
		Type:     AST_NODE_TYPE_PROGRAM,
		Children: []*ASTNode{varNode, blockNode},
		Token:    Token{},
	}
}

// block : declarations compound_statement
func (p *Parser) Block() *ASTNode {
	return &ASTNode{
		Type:     AST_NODE_TYPE_BLOCK,
		Children: append(p.DeclarationStmt(), p.CompoundStmt()),
	}
}

// declarations : VAR (variable_declaration SEMI)+ | empty
func (p *Parser) DeclarationStmt() []*ASTNode {
	ret := make([]*ASTNode, 0)
	if p.lex.CurrentToken.Type == TokenTypeKeywordVar {
		p.lex.Eat(TokenTypeKeywordVar)
		for p.lex.CurrentToken.Type == TokenTypeIdentifier {
			ret = append(ret, p.VariableDeclarationStmt())
			p.lex.Eat(TokenTypeSemi)
		}
	}
	return ret
}

// variable_declaration : ID (COMMA ID)* COLON type_spec
func (p *Parser) VariableDeclarationStmt() *ASTNode {
	varNode := &ASTNode{Type: AST_NODE_TYPE_VAR}
	for p.lex.CurrentToken.Type == TokenTypeIdentifier {
		varNode.Children = append(varNode.Children, &ASTNode{
			Type:  AST_NODE_TYPE_IDENTIFIER,
			Token: p.lex.CurrentToken,
		})
		p.lex.Eat(TokenTypeIdentifier)
		if p.lex.CurrentToken.Type != TokenTypeComma {
			break
		} else {
			p.lex.Eat(TokenTypeComma)
		}
	}
	p.lex.Eat(TokenTypeColon)
	typeNode := p.TypeSpecStmt()
	for _, ident := range varNode.Children {
		ident.Children = []*ASTNode{typeNode}
	}
	return varNode
}

// type_spec : INTEGER | REAL
func (p *Parser) TypeSpecStmt() *ASTNode {
	if p.lex.CurrentToken.Type == TokenTypeKeywordInteger {
		p.lex.Eat(TokenTypeKeywordInteger)
		return &ASTNode{
			Type:     AST_NODE_TYPE_INTEGER_TYPE,
			Children: nil,
			Token:    Token{},
		}
	}
	p.lex.Eat(TokenTypeKeywordReal)
	return &ASTNode{
		Type:     AST_NODE_TYPE_REAL_TYPE,
		Children: nil,
		Token:    Token{},
	}
}

// compound_statement : BEGIN statement_list END
func (p *Parser) CompoundStmt() *ASTNode {
	p.lex.Eat(TokenTypeKeywordBegin)
	nodes := p.StatementList()
	p.lex.Eat(TokenTypeKeywordEnd)

	return &ASTNode{
		Type:     AST_NODE_TYPE_COMPOUND,
		Children: nodes,
	}
}

// statement_list : statement | statement SEMI statement_list
func (p *Parser) StatementList() []*ASTNode {
	res := []*ASTNode{p.Statement()}
	for p.lex.CurrentToken.Type == TokenTypeSemi {
		p.lex.Eat(TokenTypeSemi)
		res = append(res, p.Statement())
	}
	return res
}

// statement : compound_statement | assignment_statement | empty
func (p *Parser) Statement() *ASTNode {
	if p.lex.CurrentToken.Type == TokenTypeKeywordBegin {
		return p.CompoundStmt()
	}
	if p.lex.CurrentToken.Type == TokenTypeIdentifier {
		return p.AssignmentStmt()
	}
	return &ASTNode{
		Type: AST_NODE_TYPE_NOOP,
	}
}

// assignment_statement : variable ASSIGN expr
func (p *Parser) AssignmentStmt() *ASTNode {
	left := p.VariableStmt()
	p.lex.Eat(TokenTypeAssign)
	right := p.Expr()
	return &ASTNode{
		Type:     AST_NODE_TYPE_ASSIGN,
		Children: []*ASTNode{left, right},
		Token: Token{
			Type:  TokenTypeAssign,
			Value: ":=",
		},
	}
}

// variable: ID
func (p *Parser) VariableStmt() *ASTNode {
	node := &ASTNode{
		Type:     AST_NODE_TYPE_IDENTIFIER,
		Children: nil,
		Token:    p.lex.CurrentToken,
	}
	p.lex.Eat(TokenTypeIdentifier)
	return node
}

func (p *Parser) EmptyStmt() *ASTNode {
	return nil
}

// expr:term((PLUS|MINUS)term)*
func (p *Parser) Expr() *ASTNode {
	left := p.Term()
	for {
		switch p.lex.CurrentToken.Type {
		case TokenTypePlus:
			p.lex.Eat(TokenTypePlus)
			left = &ASTNode{
				Type:     AST_NODE_TYPE_BIN_OP,
				Children: []*ASTNode{left, p.Term()},
				Token:    Token{Type: TokenTypePlus},
			}
		case TokenTypeMinus:
			p.lex.Eat(TokenTypeMinus)
			left = &ASTNode{
				Type:     AST_NODE_TYPE_BIN_OP,
				Children: []*ASTNode{left, p.Term()},
				Token:    Token{Type: TokenTypeMinus},
			}
		default:
			return left
		}
	}
}

// term : factor ((MUL | INTEGER_DIV | FLOAT_DIV) factor)*
func (p *Parser) Term() *ASTNode {
	left := p.Factor()
	for {
		switch p.lex.CurrentToken.Type {
		case TokenTypeMulti:
			p.lex.Eat(TokenTypeMulti)
			left = &ASTNode{
				Type:     AST_NODE_TYPE_BIN_OP,
				Children: []*ASTNode{left, p.Factor()},
				Token:    Token{Type: TokenTypeMulti},
			}
		case TokenTypeKeywordIntegerDiv:
			p.lex.Eat(TokenTypeKeywordIntegerDiv)
			left = &ASTNode{
				Type:     AST_NODE_TYPE_BIN_OP,
				Children: []*ASTNode{left, p.Factor()},
				Token:    Token{Type: TokenTypeKeywordIntegerDiv},
			}
		case TokenTypeFloatDiv:
			p.lex.Eat(TokenTypeFloatDiv)
			left = &ASTNode{
				Type:     AST_NODE_TYPE_BIN_OP,
				Children: []*ASTNode{left, p.Factor()},
				Token:    Token{Type: TokenTypeFloatDiv},
			}
		default:
			return left
		}
	}
}

// factor : PLUS factor | MINUS factor | INTEGER_CONST | REAL_CONST | LPAREN expr RPAREN | variable
func (p *Parser) Factor() *ASTNode {
	switch ct := p.lex.CurrentToken; ct.Type {
	case TokenTypeIntegerConst:
		p.lex.Eat(TokenTypeIntegerConst)
		return &ASTNode{Type: AST_NODE_TYPE_INTEGER_CONST, Token: ct}
	case TokenTypeRealConst:
		p.lex.Eat(TokenTypeRealConst)
		return &ASTNode{Type: AST_NODE_TYPE_REAL_CONST, Token: ct}
	case TokenTypeLparen:
		p.lex.Eat(TokenTypeLparen)
		v := p.Expr()
		p.lex.Eat(TokenTypeRparen)
		return v

	// 一元操作符只有一个left child
	case TokenTypePlus:
		p.lex.Eat(TokenTypePlus)
		return &ASTNode{
			Type:     AST_NODE_TYPE_UNARY_OP,
			Children: []*ASTNode{p.Factor()},
			Token:    Token{Type: TokenTypePlus, Value: nil},
		}
	case TokenTypeMinus:
		p.lex.Eat(TokenTypeMinus)
		return &ASTNode{
			Type:     AST_NODE_TYPE_UNARY_OP,
			Children: []*ASTNode{p.Factor()},
			Token:    Token{Type: TokenTypeMinus, Value: nil},
		}
	case TokenTypeIdentifier: // 标识符
		p.lex.Eat(TokenTypeIdentifier)
		return &ASTNode{
			Type:     AST_NODE_TYPE_IDENTIFIER,
			Children: nil,
			Token:    ct,
		}
	default:
		Fail(fmt.Sprintf("%v", p.lex.CurrentToken.Type))
		return nil
	}
}

func (p *Parser) Init() {
	if err := func() error {
		firstToken, err := p.lex.GetNextToken()
		if err != nil {
			Fail()
		}
		p.lex.CurrentToken = firstToken
		return nil
	}(); err != nil {
		Fail()
	}
}

func (p *Parser) Interpret() (interface{}, error) {
	return Interpret(p.Program()), nil
}

func (p *Parser) Reset(exp string) *Parser {
	p.lex = Lexer{
		RawExp: exp,
		L:      len(exp),
		Index:  0,
	}
	return p
}

func newInterpreter(exp string) *Parser {
	return &Parser{
		lex: Lexer{
			RawExp:       exp,
			L:            len(exp),
			Index:        0,
			CurrentToken: Token{},
		},
	}
}

func main() {
	r := bufio.NewReader(os.Stdin)
	interpreter := newInterpreter("")
	for {
		fmt.Printf("%s", ">>> ")
		exp, err := r.ReadString('\n')
		if err != nil {
			fmt.Printf("input error: %v", err)
			return
		}
		if len(exp) == 1 {
			continue
		}
		interpreter.Reset(exp[:len(exp)-1]).Init()
		_, err = interpreter.Interpret()
		if err != nil {
			fmt.Printf("interpret error: %v", err)
			return
		} else {
			fmt.Println(_symbolTable)
		}
	}
}
