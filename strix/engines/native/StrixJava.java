import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.lang.model.element.*;
import javax.tools.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.*;

public final class StrixJava {
    record Edit(int start, int end, String value) {}
    public static void main(String[] args) {
        try { run(args); }
        catch (Exception error) { System.err.writeBytes((error.getMessage() + "\n").getBytes(StandardCharsets.UTF_8)); System.exit(1); }
    }
    static void run(String[] args) throws Exception {
        Path file = Path.of(args[0]);
        String source = Files.readString(file, StandardCharsets.UTF_8).replaceFirst("^\uFEFF", "");
        int mode = Integer.parseInt(args[1]);
        boolean rename = mode >= 2 && args[2].equals("1");
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("Java requires a JDK, not a JRE.");
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager manager = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
            JavaFileObject input = new SimpleJavaFileObject(file.toUri(), JavaFileObject.Kind.SOURCE) {
                @Override public CharSequence getCharContent(boolean ignoreEncodingErrors) { return source; }
            };
            // No annotation processors, user build scripts or class generation are run.
            JavacTask task = (JavacTask)compiler.getTask(null, manager, diagnostics,
                List.of("-proc:none", "-implicit:none"), null, List.of(input));
            CompilationUnitTree unit = task.parse().iterator().next();
            List<String> errors = diagnostics.getDiagnostics().stream()
                .filter(d -> d.getKind() == Diagnostic.Kind.ERROR).map(Object::toString).toList();
            if (!errors.isEmpty()) throw new IllegalArgumentException(String.join("\n", errors));
            // shortcut: attribution uses platform references; add an explicit project classpath when external binding is required.
            task.analyze();
            Trees trees = Trees.instance(task);
            SourcePositions positions = trees.getSourcePositions();
            Map<Element, String> names = new HashMap<>();
            Map<Element, Edit> declarations = new HashMap<>();
            Set<String> unresolved = new HashSet<>();
            List<Edit> edits = new ArrayList<>();
            Set<String> used = new HashSet<>();
            Matcher identifiers = Pattern.compile("\\p{javaJavaIdentifierStart}\\p{javaJavaIdentifierPart}*").matcher(source);
            while (identifiers.find()) used.add(identifiers.group());
            SecureRandom random = new SecureRandom();
            new TreePathScanner<Void, Void>() {
                @Override public Void visitIdentifier(IdentifierTree node, Void unused) {
                    if (trees.getElement(getCurrentPath()) == null) unresolved.add(node.getName().toString());
                    return super.visitIdentifier(node, unused);
                }
                @Override public Void visitVariable(VariableTree node, Void unused) {
                    Element symbol = trees.getElement(getCurrentPath());
                    if (rename && symbol != null && Set.of(ElementKind.LOCAL_VARIABLE,
                        ElementKind.RESOURCE_VARIABLE, ElementKind.BINDING_VARIABLE).contains(symbol.getKind())) {
                        int start = (int)positions.getStartPosition(unit, node);
                        int end = (int)positions.getEndPosition(unit, node);
                        if (node.getInitializer() != null) end = (int)positions.getStartPosition(unit, node.getInitializer());
                        if (start >= 0 && end >= start && end <= source.length()) {
                            String original = node.getName().toString();
                            Matcher matcher = Pattern.compile("(?<![\\p{javaJavaIdentifierPart}])" + Pattern.quote(original)
                                + "(?![\\p{javaJavaIdentifierPart}])").matcher(source.substring(start, end));
                            if (matcher.find()) {
                                int nameStart = start + matcher.start(), nameEnd = start + matcher.end();
                                // Ambiguous or escaped declaration spellings keep their original binding.
                                if (!matcher.find()) {
                                    String name;
                                    do { byte[] bytes = new byte[mode == 3 ? 16 : 8]; random.nextBytes(bytes);
                                        name = "s" + HexFormat.of().formatHex(bytes); }
                                    while (!used.add(name));
                                    names.put(symbol, name);
                                    declarations.put(symbol, new Edit(nameStart, nameEnd, name));
                                }
                            }
                        }
                    }
                    return super.visitVariable(node, unused);
                }
            }.scan(unit, null);
            names.entrySet().removeIf(entry -> unresolved.contains(entry.getKey().getSimpleName().toString()));
            declarations.keySet().retainAll(names.keySet());
            edits.addAll(declarations.values());
            new TreePathScanner<Void, Void>() {
                @Override public Void visitIdentifier(IdentifierTree node, Void unused) {
                    String name = names.get(trees.getElement(getCurrentPath()));
                    if (name != null) add(node, name);
                    return super.visitIdentifier(node, unused);
                }
                @Override public Void visitLiteral(LiteralTree node, Void unused) {
                    if (node.getKind() == Tree.Kind.STRING_LITERAL && node.getValue() instanceof String value) {
                        List<String> chunks = new ArrayList<>();
                        int size = mode == 3 ? 8 : Math.max(1, value.length());
                        for (int index = 0; index < value.length(); index += size) {
                            StringBuilder text = new StringBuilder("\"");
                            for (int i = index; i < Math.min(index + size, value.length()); i++) {
                                char c = value.charAt(i);
                                text.append(c < 256 ? String.format("\\%03o", (int)c) : String.format("\\u%04x", (int)c));
                            }
                            chunks.add(text.append('"').toString());
                        }
                        if (chunks.isEmpty()) chunks.add("\"\"");
                        add(node, chunks.size() == 1 ? chunks.get(0) : "(" + String.join(" + ", chunks) + ")");
                    }
                    return super.visitLiteral(node, unused);
                }
                void add(Tree node, String value) {
                    int start = (int)positions.getStartPosition(unit, node), end = (int)positions.getEndPosition(unit, node);
                    if (start >= 0 && end >= start && end <= source.length()) {
                        long lines = source.substring(start, end).chars().filter(c -> c == '\n').count();
                        edits.add(new Edit(start, end, value + "\n".repeat((int)lines)));
                    }
                }
            }.scan(unit, null);
            edits.sort(Comparator.comparingInt(Edit::start));
            // shortcut: comments are preserved; add a compiler lexer when Java comment removal is required.
            StringBuilder output = new StringBuilder();
            int position = 0;
            for (Edit edit : edits) {
                if (edit.start() < position) throw new IllegalStateException("Overlapping Java source edits.");
                output.append(source, position, edit.start()).append(edit.value());
                position = edit.end();
            }
            output.append(source, position, source.length());
            if (args.length > 3) Files.writeString(Path.of(args[3]), output, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
            else System.out.writeBytes(output.toString().getBytes(StandardCharsets.UTF_8));
        }
    }
}
