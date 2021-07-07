//A parser for extracting comments out of a string
// https://nolanlawson.github.io/jison-debugger/
//Lexical Grammer
%lex

NoBrack   ([^\b\v\n\r\]\[])
Letter    ([a-zA-Z_])
Number    ([0-9])
GetField  (\|\-\>)

//%options flex
%x OSQLQUERY SQLQUERYQUATE1 SQLQUERYQUATE2 NOBRACK OVarRef ORECIP ORecipRef OTableFieldRef OFieldRef DQuote SQuote DateQuote RemarkBlock RemarkLine


%%

([ \n\r\t])													{ /**/}
"/*"														{ /**/ this.pushState('RemarkBlock'); yytext=""; /*ignore*/}
"//"														{ /**/ this.pushState('RemarkLine'); yytext="";  /*ignore*/} 
"("															{ /**/ return 'OParen'; }
")"															{ /**/ return 'CParen'; }
"{"															{ /**/ return 'SOParen'; }
"}"															{ /**/ return 'SCParen'; }
"\""														{ /**/ this.pushState('DQuote');return 'SQUATE'; }
"'"														{ /**/ this.pushState('SQuote');return 'SQUATE'; }
({Number}+(\.{Number}+)?)									{ /**/ return 'NUMBER';}
(\.{Number}+)												{ /**/ return 'NUMBER';}
"#"															{ /**/ this.pushState('DateQuote');return 'SDATE'; }
"@{"														{ /**/ this.pushState('OVarRef');return 'SID'; }
"|->"														{ /**/ this.pushState('ORECIP'); /*ignore*/ }
({GetField})													{ /**/ this.pushState('ORECIP'); /*ignore*/ }
"?"															{ /**/ return 'RID'; }
"["															{ /**/ this.pushState('NOBRACK');return 'SREF'; }
"]["														{ /**/ return 'MREF1'; }
"].["														{ /**/ this.pushState('NOBRACK');return 'MREF2'; }
"]"															{ /**/ return 'EREF';}
([rR][eE][pP][oO][rR][tT][Mm][eE][sS][sS][aA][gG][eE])											{ /**/ return 'ReportMessage'; }
([aA][bB][oO][rR][tT])														{ /**/ return 'CONTROL'; }
([sS][kK][iI][pP])														{ /**/ return 'CONTROL'; }
([iI][nN][sS][eE][rR][tT])													{ /**/ this.pushState('OSQLQUERY');return 'QUERYTYPE'; }
([uU][pP][dD][aA][tT][eE])													{ /**/ this.pushState('OSQLQUERY');return 'QUERYTYPE'; }
([sS][eE][lL][eE][cC][tT])													{ /**/ this.pushState('OSQLQUERY');return 'QUERYTYPE'; }
([eE][xX][eE][cC][uU][tT][eE])													{ /**/ this.pushState('OSQLQUERY');return 'QUERYTYPE'; }
([dD][eE][lL][eE][tT][eE])													{ /**/ this.pushState('OSQLQUERY');return 'QUERYTYPE'; }
([cC][aA][lL][lL])														{ /**/ return 'CALL'; }
([iI][fF])														{ /**/ return 'IF'; }
([eE][lL][sS][eE])													{ /**/ return 'ELSE'; }
([fF][aA][lL][sS][eE])														{ /**/return 'CONST'; }
([tT][rR][uU][eE])														{ /**/return 'CONST'; }
([nN][uU][lL][lL])														{ /**/return 'CONST'; }
([sS][wW][iI][tT][cC][hH])													{ /**/ return 'SWITCH'; }
([cC][aA][sS][eE])														{ /**/ return 'CASE'; }
([dD][eE][fF][aA][uU][lL][tT])													{ /**/ return 'DEFAULT'; }
([aA][nN][dD])														{ /**/ return 'AND'; }
([oO][rR])														{ /**/ return 'OR'; }
([nN][oO][tT])														{ /**/ return 'NOT'; }
([dD][iI][vV])												{ /**/ return 'DIV'; }
([mM][oO][dD])														{ /**/ return 'MOD'; }
"%"															{ /**/ return 'MOD'; }
"+"															{ /**/ return 'PLUS'; }
"-"															{ /**/ return 'MINUS'; }
"&"															{ /**/ return 'CONCAT'; }
":="														{ /**/ return 'ASSIGN'; }
"=="														{ /**/ return 'EQ'; }
"!="														{ /**/ return 'NOTEQ'; }
"<>"														{ /**/ return 'NOTEQ'; }
">="														{ /**/ return 'GRETTEREQ'; }
"<="														{ /**/ return 'SMALLEREQ'; }
"!"															{ /**/ return 'NOT'; }
":"															{ /**/ return 'COLONS'; }
"."															{ /**/ return 'COLON'; }
","															{ /**/ return 'DELIMITER'; }
"*"														{ /**/ return 'MUL'; }
"/"															{ /**/ return 'DEV'; }
"="															{ /**/ return 'EQ'; }
">"															{ /**/ return 'GRETTER'; }
"<"															{ /**/ return 'SMALLER'; }
({Letter}({Letter}|{Number})*)								return 'ID';
<<EOF>> 													return "EOF";
<OSQLQUERY>(\|\-\>)											{ /**/ this.pushState('ORECIP'); /*ignore*/ }
<OSQLQUERY>"@{"												{ /**/ this.pushState('OVarRef'); return 'SID'; }
<OSQLQUERY>"@["												{ /**/ this.pushState('OTableFieldRef');return 'STABLE_FIELD'; }
//] For syntax higlight bug
<OSQLQUERY>"\""												{ /**/ this.pushState('SQLQUERYQUATE1'); return 'QUERYPART'; }
<OSQLQUERY>"'"												{ /**/ this.pushState('SQLQUERYQUATE2'); return 'QUERYPART'; }
<OSQLQUERY>(\[([ \t])*\?([ \t])*\]|\?)						{ /**/ return 'RID';}
<OSQLQUERY>";"												{ /**/ this.popState(); return 'QUERYEND'; }
<OSQLQUERY>([^\?\"';])										{ /**/ return 'QUERYPART'; }

<SQLQUERYQUATE1>([^\"])										{ /**/ return 'QUERYPART'; }
<SQLQUERYQUATE1>"\""										{ /**/ this.popState(); return 'QUERYPART'; }

<SQLQUERYQUATE2>([^'])										{ /**/ return 'QUERYPART'; }
<SQLQUERYQUATE2>"'"										{ /**/ this.popState(); return 'QUERYPART'; }


<NOBRACK>({NoBrack}+)										{ /**/ this.popState(); return 'NOBRACKSTR'; }


<OVarRef>([^\b\v\n\r\}\{]+)									{ /**/ return 'ID'; }
<OVarRef>"}"												{ /**/ this.popState(); return 'EID'; }

<ORECIP>(({Letter}({Letter}|{Number})*)|\?)					{ /**/ this.popState(); return 'RID'; }
<ORECIP>"["													{ /**/ this.pushState('ORecipRef'); return 'SRID'; }
//] higlight bug
<ORecipRef>({NoBrack}+)										{ /**/ return 'RID'; }
<ORecipRef>"]"												{ /**/ this.popState();this.popState(); return 'ERID'; }

<OTableFieldRef>({NoBrack}+)								{ /**/ return 'TABLE_FIELD'; }
<OTableFieldRef>"].["										{ /**/ this.pushState('OFieldRef'); /*ignore*/ }
//] higlight bug
<OTableFieldRef>"]"											{ /**/ this.popState(); return 'ETABLE_FIELD'; }

<OFieldRef>({NoBrack}+)										{ /**/ return 'FIELD'; }	
<OFieldRef>"]"												{ /**/ this.popState();this.popState(); return 'ETABLE_FIELD'; }

<DQuote>"\""												{ /**/ this.popState(); return 'EQUATE'; }
<DQuote>((([^\"\\])|(\\.))*)								{ /**/ return 'QuotePART'; }

<SQuote>"'"												{ /**/ this.popState(); return 'EQUATE'; }
<SQuote>((([^'\\])|(\\.))*)								{ /**/ return 'QuotePART'; }


<DateQuote>"#"												{ /**/ this.popState(); return 'EDATE'; }
<DateQuote>((([012][0-9])|(3[01]))[\/]((0[0-9])|(1[012]))[\/]([0-9][0-9]){1,2})	{ /**/ return 'DATE'; }
<DateQuote>((([012][0-9])|(3[01]))[\.]((0[0-9])|(1[012]))[\.]([0-9][0-9]){1,2})	{ /**/ return 'DATE'; }
<DateQuote>((([012][0-9])|(3[01]))[\\]((0[0-9])|(1[012]))[\\]([0-9][0-9]){1,2})	{ /**/ return 'DATE'; }
<DateQuote>((([012][0-9])|(3[01]))[\-]((0[0-9])|(1[012]))[\-]([0-9][0-9]){1,2})	{ /**/ return 'DATE'; }

<RemarkBlock>"*/"														{ /**/ this.popState();/*ignore*/ }
<RemarkBlock>"/*"														{ /**/ this.pushState('RemarkBlock'); /*ignore*/ }
//*/ For syntax higlight bug
<RemarkBlock>(.|\n)													{ /**/ /*ignore*/ }



<RemarkLine>([\r\n])														{ /**/ this.popState(); /*ignore*/ }
<RemarkLine>(.)															{ /**/}
//End of nested states

/lex


%right ':='		
%right ELSE
%left OR '||'
%left '&&' AND
%left '|'
%left '^'
%left '&'
%nonassoc EQ NOTEQ		
%nonassoc SMALLEREQ GRETTEREQ	GRETTER	SMALLER	
%left PLUS MINUS
%left MUL 
%left DEV
%left DIV MOD 
%right NOT
%left COLON
%left DELIMITER 

//%start expr
//%s expr block literal
//Parsing Grammer
%%


main
: expr 
| expr EOF
;

expr
	: ArithmeticUnaryMinus
	| ArithmeticUnaryPlus
	| ArithmeticPlus
	| ArithmeticMinus
	| ArithmeticMul
	| ArithmeticDev
	| ArithmeticDiv
	| ArithmeticMod
	| ArithmeticConcat
	| PredicateEq
	| PredicateNotEq
	| PredicateGretterEq
	| PredicateSmallerEq
	| PredicateGretter
	| PredicateSmaller
	| PredicateNot
	| PredicateAnd
	| PredicateOr 
	| ExprParren { /**/ }
	| ExprConst
	| ExprLiteral { /**/ }
	| ExprVariableRef1
	| ExprVariableRef2
	| ExprRecipRef1
	| ExprRecipRef2
	| UVExpr
	| UVRowExpr
	| UVFieldExpr
	| UVRowFieldExpr
	| UserFunctionCall
	| ExtentionFunctionCall
	| ExprDSQuery1
	| ExprDSQuery2
	| ExprQuery
	| ExprControl
	| ExprIf
	| ExprIfElse
	| ExprSwitch
	| ExprRecipAssign1
	| ExprRecipAssign2
	| MessageExpr
	;
ExprParren						
	: OParen expr CParen { /**/ $$ = $1 + $2 + $3 }
	;
ExprConst						
	: CONST
	;
ExprLiteral						
	: literal { /**/ $$ = $1; }
	;
// var referances
ExprVariableRef1				
	: ID
	;
ExprVariableRef2				
	: SID ID EID { $$ = $1 + $2+ $3 }
	;
ExprRecipRef1					
	: RID
	;
ExprRecipRef2					
	: SRID RID ERID { $$ = $1 + $2+ $3 }
	;

// user view reference
UVExpr							
	: SREF NOBRACKSTR EREF { $$ = $1 + $2+ $3 }
	;
UVRowExpr						
	: SREF NOBRACKSTR MREF1 expr EREF { $$ = $1 + $2+ $3+ $4+ $5 }
	;
UVFieldExpr						
	: SREF NOBRACKSTR MREF2 NOBRACKSTR EREF { $$ = $1 + $2+ $3+ $4+ $5 }
	;
UVRowFieldExpr					
	: SREF NOBRACKSTR MREF1 expr MREF2 NOBRACKSTR EREF { $$ = $1 + $2+ $3+ $4+ $5+ $6+ $7 }
	;
// function
UserFunctionCall				
	: ID OParen paramlist CParen { $$ = $1 + $2+ $3+ $4 }
	;
ExtentionFunctionCall			
	: CALL ID COLON ID OParen paramlist CParen { $$ = $1 + $2+ $3+ $4+ $5+ $6+ $7 }
	;
// sql query
ExprDSQuery1					
	: ID COLONS ExprQueryType querypartlist { $$ = $1 + $2 + $3 + $4 }
	;
ExprDSQuery2					
	: SID ID EID COLONS ExprQueryType querypartlist { $$ = $1 + $2+ $3+ $4 + $5 + $6 }
	;
ExprQuery						
	: ExprQueryType querypartlist { $$ = $1 + $2 }
	;
ExprQueryType
	: QUERYTYPE
	;
// control
ExprControl						
	: CONTROL
	;

// if-then-else
ExprIf							
	: IF OParen expr CParen block { $$ = $1 + $2+ $3+ $4+ $5 }
	;
ExprIfElse						
	: IF OParen expr CParen block ELSE block { $$ = $1 + $2+ $3+ $4+ $5+ $6+ $7 }
	;
ExprSwitch
	: SWITCH OParen expr CParen SOParen caseslist SCParen { $$ = $1 + $2+ $3+ $4+ $5+ $6+ $7 }
	;
ArithmeticUnaryMinus
	: MINUS expr { $$ = $1 + $2 }
	;
ArithmeticUnaryPlus
	:  expr { $$ = $1 + $2 }
	;
ArithmeticPlus
	: expr PLUS expr { $$ = $1 + $2 + $3 }
	;
ArithmeticMinus
	: expr MINUS expr { $$ = $1 + $2 + $3 }
	;
ArithmeticMul
	: expr MUL expr { $$ = $1 + $2 + $3 }
	;
ArithmeticDev
	: expr DEV expr { $$ = $1 + $2 + $3 }
	;
ArithmeticDiv
	: expr DIV expr { $$ = $1 + $2 + $3 }
	;
ArithmeticMod
	: expr MOD expr { $$ = $1 + $2 + $3 }
	;
ArithmeticConcat
	: expr CONCAT expr { $$ = $1 + $2 + $3 }
	;
PredicateEq
	: expr EQ expr { $$ = $1 + $2 + $3 }
	;
PredicateNotEq
	: expr NOTEQ expr { $$ = $1 + $2 + $3 }
	;
PredicateGretterEq
	: expr GRETTEREQ expr { $$ = $1 + $2 + $3 }
	;
PredicateSmallerEq
	: expr SMALLEREQ expr { $$ = $1 + $2 + $3 }
	;
PredicateGretter
	: expr GRETTER expr { $$ = $1 + $2 + $3 }
	;
PredicateSmaller
	: expr SMALLER expr { $$ = $1 + $2 + $3 }
	;
PredicateNot
	: NOT expr { $$ = $1 + $2 }
	;
PredicateAnd
	: expr AND expr { $$ = $1 + $2 + $3 }
	;
PredicateOr
	: expr OR expr { $$ = $1 + $2 + $3 }
	;
ExprRecipAssign1
	: RID ASSIGN expr { $$ = $1 + $2 + $3 }
	;

ExprRecipAssign2
	: SRID RID ERID ASSIGN expr { $$ = $1 + $2 + $3 + $4 + $5 }
	;
MessageExpr
	: ReportMessage OParen expr CParen expr { $$ = $1 + $2 + $3 + $4 + $5 }
	;

block
	: ExprBracketBlock
	| ExprSingleExprBlock
	;
ExprBracketBlock
	: SOParen expr SCParen
	;
ExprSingleExprBlock
	: expr
	;
literal
	: LiteralEString
	| LiteralString
	| LiteralNumber
	| LiteralDate
	;
LiteralEString
	: SQUATE EQUATE { $$ = $1 + $2 }
	;
LiteralString
	: SQUATE QuotePART EQUATE { $$ = $1 + $2 + $3 }
	;
LiteralNumber
	: NUMBER
	;
LiteralDate
	: SDATE DATE EDATE { $$ = $1 + $2 + $3 }
	;
paramlist
	: FuncParams
	| 
	;
FuncNoParams					
	:
	;
FuncParams
	: paramlistcont
	;
paramlistcont
	: FuncMidParam
	;
FuncMidParam					
	: expr DELIMITER paramlistcont { $$ = $1 + $2 + $3 }
	| expr
	;
FuncLastParam					
	: expr
	;
querypartlist
	: QueryPartConst		
	| QueryPartVarRef		
	| QueryPartRecipRef1	
	| QueryPartRecipRef2	
	| QueryFieldNameRef	
	| QueryTableNameRef	
	| QueryPartEnd1		
	| QueryPartEnd2
	| { $$ = ''}
	;
QueryPartConst					
	: QueryParts querypartlist { $$ = $1 + $2 }
	;
QueryParts
	: QUERYPART
	| QueryParts QUERYPART { $$ = $1 + $2 }
	;
QueryPartVarRef					
	: SID ID EID querypartlist { $$ = $1 + $2 + $3 + $4 }
	;
QueryPartRecipRef1				
	: RID querypartlist { $$ = $1 + $2 }
	;
QueryPartRecipRef2				
	: SRID RID ERID querypartlist { $$ = $1 + $2 + $3 + $4 }
	;
QueryFieldNameRef				
	: QueryTableFieldName querypartlist { $$ = $1 + $2 }
	;

QueryTableNameRef				
	: QueryTableName querypartlist { $$ = $1 + $2 }
	;
QueryTableName
	: STABLE_FIELD TABLE_FIELD ETABLE_FIELD { $$ = $1 + $2 + $3 }
	;
QueryTableFieldName
	: STABLE_FIELD TABLE_FIELD FIELD ETABLE_FIELD { $$ = $1 + $2 + '.' + $3 + $4 }
	;

QueryPartEnd1					
	: QUERYEND
	;
QueryPartEnd2					
	: <<EOF>>
	;
caseslist
	:CasesListMid		
	| CasesListLastCase	
	| CasesListDefault	
	;

CasesListMid					
	: CASE literal COLONS block caseslist { $$ = $1 + $2 + $3 + $4 + $5 }
	;
CasesListLastCase				
	: CASE literal COLONS block { $$ = $1 + $2 + $3 + $4 }
	;
CasesListDefault				
	: DEFAULT COLONS block { $$ = $1 + $2 + $3 }
	;


%%
var print = function(token,text){
	console.log(token,text);
}
var getTypes = function (types) {
	types = types.split(',');
	var Types = {};
	for (var i in types) {
		Types[types[i]] = true;
        
	}
    console.log("Types:" + Object.keys(Types)[0]);
	return Types;
};

var convertToSyntax = function (type, body) {
    var tp = Object.keys(type).filter(t=>t)[0]
    if (tp) {
        return type + body;
    }
    return JSON.stringify(type);
};
var validateFieldName = function(name){
    return true;
}