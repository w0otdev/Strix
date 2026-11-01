/* Local compilation only. Input source is never evaluated by this driver. */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const ts = require('typescript');
const obfuscator = require('javascript-obfuscator');

function compile(filename, mode, more) {
    const source = new TextDecoder('utf-8', {fatal: true}).decode(fs.readFileSync(filename));
    const configFile = ts.findConfigFile(path.dirname(filename), ts.sys.fileExists);
    let configured = {};
    if (configFile) {
        const read = ts.readConfigFile(configFile, ts.sys.readFile);
        if (read.error) throw new Error(ts.flattenDiagnosticMessageText(read.error.messageText, '\n'));
        const converted = ts.parseJsonConfigFileContent(read.config, ts.sys, path.dirname(configFile), {}, configFile);
        const errors = converted.errors.filter(item => item.code !== 18003); // Empty include lists do not affect per-file emit.
        if (errors.length) throw new Error(ts.formatDiagnostics(errors, host));
        configured = converted.options;
    }
    // Emit runtime JavaScript, retaining ESM/CommonJS and the project's JSX factories.
    // No bundling: dependencies, public exports, properties and file resources stay intact.
    const options = {
        target: ts.ScriptTarget.ESNext,
        module: ts.ModuleKind.Preserve,
        jsx: [ts.JsxEmit.ReactJSX, ts.JsxEmit.ReactJSXDev].includes(configured.jsx)
            ? configured.jsx : ts.JsxEmit.React,
        jsxFactory: configured.jsxFactory,
        jsxFragmentFactory: configured.jsxFragmentFactory,
        jsxImportSource: configured.jsxImportSource,
        experimentalDecorators: configured.experimentalDecorators,
        emitDecoratorMetadata: configured.emitDecoratorMetadata,
        useDefineForClassFields: configured.useDefineForClassFields,
        verbatimModuleSyntax: configured.verbatimModuleSyntax,
        rewriteRelativeImportExtensions: true,
        sourceMap: false,
        removeComments: false,
    };
    function emittedSpecifier(text) {
        if (!/^\.{1,2}\//.test(text) || /\.d\.(?:ts|mts|cts)$/.test(text)) return text;
        return text.replace(/\.(tsx?|jsx|mts|cts)$/, extension => ({
            '.ts': '.js', '.tsx': '.js', '.jsx': '.js', '.mts': '.mjs', '.cts': '.cjs',
        })[extension]);
    }
    // Rewrite all static runtime paths, including require() (not handled by tsc).
    function jsxPaths(context) {
        return root => ts.visitNode(root, function visit(node) {
            const specifier = ts.isImportDeclaration(node) || ts.isExportDeclaration(node)
                ? node.moduleSpecifier : undefined;
            if (specifier && ts.isStringLiteral(specifier) && emittedSpecifier(specifier.text) !== specifier.text) {
                const replacement = ts.factory.createStringLiteral(emittedSpecifier(specifier.text));
                if (ts.isImportDeclaration(node)) {
                    return ts.factory.updateImportDeclaration(node, node.modifiers, node.importClause, replacement, node.attributes);
                }
                return ts.factory.updateExportDeclaration(node, node.modifiers, node.isTypeOnly, node.exportClause, replacement, node.attributes);
            }
            if (ts.isExternalModuleReference(node) && ts.isStringLiteral(node.expression)) {
                const text = emittedSpecifier(node.expression.text);
                return ts.factory.updateExternalModuleReference(node, ts.factory.createStringLiteral(text));
            }
            if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword
                || (ts.isIdentifier(node.expression) && node.expression.text === 'require'))) {
                const args = node.arguments.map(arg => ts.isStringLiteralLike(arg)
                    && emittedSpecifier(arg.text) !== arg.text
                    ? ts.factory.createStringLiteral(emittedSpecifier(arg.text)) : arg);
                node = ts.factory.updateCallExpression(node, node.expression, node.typeArguments, args);
            }
            return ts.visitEachChild(node, visit, context);
        });
    }
    const result = ts.transpileModule(source, {
        fileName: filename,
        compilerOptions: options,
        reportDiagnostics: true,
        transformers: {before: [jsxPaths]},
    });
    const errors = (result.diagnostics || []).filter(item => item.category === ts.DiagnosticCategory.Error);
    if (errors.length) throw new Error(ts.formatDiagnostics(errors, host));
    const reserved = new Set();
    if (!more) {
        const tree = ts.createSourceFile(filename + '.js', result.outputText, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
        function collect(node) {
            if (ts.isIdentifier(node)) reserved.add('^' + node.text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$');
            ts.forEachChild(node, collect);
        }
        collect(tree);
    }
    // No hooks, eval wrappers or renamed public properties. Separate files share APIs.
    const full = mode >= 2;
    const mega = mode === 3;
    const obfuscated = obfuscator.obfuscate(result.outputText, {
        compact: true,
        target: 'browser-no-eval',
        seed: crypto.randomInt(1, 0x7fffffff),
        identifiersPrefix: '_s' + crypto.randomBytes(6).toString('hex'),
        identifierNamesGenerator: 'hexadecimal',
        reservedNames: [...reserved],
        renameGlobals: false,
        renameProperties: false,
        ignoreImports: true,
        stringArray: true,
        stringArrayThreshold: full ? 1 : 0.5,
        stringArrayEncoding: full ? ['base64'] : [],
        stringArrayCallsTransform: full && more,
        stringArrayRotate: full,
        stringArrayShuffle: true,
        stringArrayIndexShift: true,
        splitStrings: full && more,
        splitStringsChunkLength: mega ? 4 : 10,
        numbersToExpressions: full && more,
        controlFlowFlattening: full && more,
        controlFlowFlatteningThreshold: mega ? 0.75 : 0.35,
        deadCodeInjection: mega && more,
        deadCodeInjectionThreshold: 0.2,
        transformObjectKeys: false,
        selfDefending: false,
        debugProtection: false,
        sourceMap: false,
    }).getObfuscatedCode();
    return obfuscated + '\n';
}

const host = {
    getCanonicalFileName: file => file,
    getCurrentDirectory: () => process.cwd(),
    getNewLine: () => '\n',
};
try {
    const output = compile(path.resolve(process.argv[2]), Number(process.argv[3]), process.argv[4] === '1');
    if (process.argv[5]) {
        fs.writeFileSync(process.argv[5], output, {encoding: 'utf8', flag: 'wx'});
    } else {
        process.stdout.write(output);
    }
} catch (error) {
    process.stderr.write(String(error.message || error) + '\n');
    process.exitCode = 1;
}
