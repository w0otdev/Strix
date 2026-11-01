using System.Security.Cryptography;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

try
{
    Console.OutputEncoding = new UTF8Encoding(false);
    var source = File.ReadAllText(args[0], new UTF8Encoding(false, true));
    var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Latest), args[0]);
    var errors = tree.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToArray();
    if (errors.Length != 0) throw new InvalidOperationException(string.Join("\n", errors.Select(d => d.ToString())));
    var references = ((string?)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") ?? "")
        .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).Select(p => MetadataReference.CreateFromFile(p));
    // shortcut: binding uses one file and platform references; use a project model when external symbols need full resolution.
    var compilation = CSharpCompilation.Create("StrixInput", new[] { tree }, references,
        new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, allowUnsafe: true));
    var model = compilation.GetSemanticModel(tree, ignoreAccessibility: true);
    var mode = int.Parse(args[1]);
    var more = args[2] == "1";
    var root = tree.GetRoot();
    var names = new Dictionary<ISymbol, string>(SymbolEqualityComparer.Default);
    var blocked = new HashSet<ISymbol>(SymbolEqualityComparer.Default);
    var unresolved = new HashSet<string>();
    var used = root.DescendantTokens().Where(t => t.IsKind(SyntaxKind.IdentifierToken)).Select(t => t.ValueText).ToHashSet();
    // shortcut: conditional source retains local names; upgrade to a project/configuration model before renaming inactive branches.
    var conditional = root.DescendantTrivia(descendIntoTrivia: true).Any(t => t.IsKind(SyntaxKind.DisabledTextTrivia) || t.GetStructure() is IfDirectiveTriviaSyntax);
    if (more && mode >= 2 && !conditional)
    {
        foreach (var node in root.DescendantNodes())
        {
            ISymbol? symbol = node switch
            {
                VariableDeclaratorSyntax variable => model.GetDeclaredSymbol(variable),
                SingleVariableDesignationSyntax variable => model.GetDeclaredSymbol(variable),
                ForEachStatementSyntax variable => model.GetDeclaredSymbol(variable),
                _ => null,
            };
            if (symbol is not ILocalSymbol) continue;
            string name;
            do { name = "s" + Convert.ToHexString(RandomNumberGenerator.GetBytes(mode == 3 ? 16 : 8)).ToLowerInvariant(); }
            while (!used.Add(name));
            names[symbol] = name;
        }
        foreach (var node in root.DescendantNodes().OfType<IdentifierNameSyntax>())
        {
            var symbol = model.GetSymbolInfo(node).Symbol;
            if (symbol is null) { unresolved.Add(node.Identifier.ValueText); continue; }
            if (!names.ContainsKey(symbol)) continue;
            if (node.Parent is AnonymousObjectMemberDeclaratorSyntax { NameEquals: null }
                || node.Parent is ArgumentSyntax { NameColon: null, Parent: TupleExpressionSyntax }
                || node.Ancestors().OfType<InvocationExpressionSyntax>().Any(call =>
                    call.Expression is IdentifierNameSyntax { Identifier.ValueText: "nameof" }
                    || model.GetSymbolInfo(call).Symbol is not IMethodSymbol method
                    || method.Parameters.Any(p => p.GetAttributes().Any(a => a.AttributeClass?.Name == "CallerArgumentExpressionAttribute")))
                || node.Ancestors().OfType<BaseObjectCreationExpressionSyntax>().Any(call =>
                    model.GetSymbolInfo(call).Symbol is not IMethodSymbol method
                    || method.Parameters.Any(p => p.GetAttributes().Any(a => a.AttributeClass?.Name == "CallerArgumentExpressionAttribute"))))
                blocked.Add(symbol);
        }
        foreach (var symbol in blocked) names.Remove(symbol);
        foreach (var symbol in names.Keys.Where(s => unresolved.Contains(s.Name)).ToArray()) names.Remove(symbol);
    }
    var output = new Rewriter(model, names, mode).Visit(root)!.ToFullString();
    if (args.Length > 3)
    {
        using var stream = new FileStream(args[3], FileMode.CreateNew, FileAccess.Write);
        using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        writer.Write(output);
    }
    else Console.Write(output);
}
catch (Exception error)
{
    Console.Error.WriteLine(error.Message);
    Environment.ExitCode = 1;
}

sealed class Rewriter(SemanticModel model, Dictionary<ISymbol, string> names, int mode) : CSharpSyntaxRewriter
{
    public override SyntaxToken VisitToken(SyntaxToken token)
    {
        if (token.IsKind(SyntaxKind.IdentifierToken))
        {
            var parent = token.Parent!;
            ISymbol? symbol = parent switch
            {
                IdentifierNameSyntax node => model.GetSymbolInfo(node).Symbol,
                VariableDeclaratorSyntax node => model.GetDeclaredSymbol(node),
                SingleVariableDesignationSyntax node => model.GetDeclaredSymbol(node),
                ForEachStatementSyntax node => model.GetDeclaredSymbol(node),
                _ => null,
            };
            if (symbol is not null && names.TryGetValue(symbol, out var name))
                return SyntaxFactory.Identifier(token.LeadingTrivia, name, token.TrailingTrivia);
        }
        return base.VisitToken(token);
    }

    public override SyntaxNode? VisitLiteralExpression(LiteralExpressionSyntax node)
    {
        // shortcut: comments, interpolated and UTF-8 strings stay intact; add specialized token rewrites when those forms need encoding.
        if (!node.IsKind(SyntaxKind.StringLiteralExpression)) return base.VisitLiteralExpression(node);
        var value = node.Token.ValueText;
        var chunks = new List<string>();
        var size = mode == 3 ? 8 : Math.Max(1, value.Length);
        for (var index = 0; index < value.Length; index += size)
        {
            var text = new StringBuilder("\"");
            for (var offset = index; offset < Math.Min(index + size, value.Length); offset++)
                text.Append("\\u").Append(((int)value[offset]).ToString("x4"));
            chunks.Add(text.Append('"').ToString());
        }
        if (chunks.Count == 0) chunks.Add("\"\"");
        var expression = chunks.Count == 1 ? chunks[0] : "(" + string.Join(" + ", chunks) + ")";
        var lines = node.Token.Text.Count(c => c == '\n');
        return SyntaxFactory.ParseExpression(expression).WithLeadingTrivia(node.GetLeadingTrivia()).WithTrailingTrivia(
                new[] { SyntaxFactory.Whitespace(new string('\n', lines)) }.Concat(node.GetTrailingTrivia()));
    }
}
