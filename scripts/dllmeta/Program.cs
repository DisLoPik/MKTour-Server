// Dump type/field/property/method metadata (with fully-qualified type names and custom attribute
// arguments) from Il2CppDumper DummyDll assemblies to JSON.
//   dotnet run -- <DummyDll dir> <out.json> [assembly name filter, comma separated]
using System.Text.Json;
using Mono.Cecil;

var dir = args[0];
var outPath = args[1];
var filter = args.Length > 2 ? args[2].Split(',').Select(s => s.Trim()).ToHashSet() : null;

var resolver = new DefaultAssemblyResolver();
resolver.AddSearchDirectory(dir);
var rp = new ReaderParameters { AssemblyResolver = resolver };

object Arg(CustomAttributeArgument a)
{
    if (a.Value is CustomAttributeArgument inner) return Arg(inner);
    if (a.Value is CustomAttributeArgument[] arr) return arr.Select(Arg).ToList();
    if (a.Value is TypeReference tr) return tr.FullName;
    return a.Value;
}

List<object> Attrs(ICustomAttributeProvider p)
{
    var list = new List<object>();
    if (!p.HasCustomAttributes) return list;
    foreach (var ca in p.CustomAttributes)
    {
        var d = new Dictionary<string, object> { ["type"] = ca.AttributeType.FullName };
        try
        {
            d["args"] = ca.ConstructorArguments.Select(Arg).ToList();
            var named = new Dictionary<string, object>();
            foreach (var f in ca.Fields) named[f.Name] = Arg(f.Argument);
            foreach (var pr in ca.Properties) named[pr.Name] = Arg(pr.Argument);
            d["named"] = named;
        }
        catch (Exception e) { d["error"] = e.Message; }
        list.Add(d);
    }
    return list;
}

var types = new List<object>();
foreach (var file in Directory.GetFiles(dir, "*.dll").OrderBy(f => f))
{
    var asmName = Path.GetFileName(file);
    if (filter != null && !filter.Contains(asmName)) continue;
    AssemblyDefinition asm;
    try { asm = AssemblyDefinition.ReadAssembly(file, rp); }
    catch (Exception e) { Console.Error.WriteLine($"{asmName}: {e.Message}"); continue; }
    foreach (var t in asm.MainModule.GetTypes())
    {
        types.Add(new Dictionary<string, object>
        {
            ["assembly"] = asmName,
            ["full"] = t.FullName,
            ["namespace"] = t.Namespace,
            ["name"] = t.Name,
            ["declaring"] = t.DeclaringType?.FullName,
            ["base"] = t.BaseType?.FullName,
            ["interfaces"] = t.Interfaces.Select(i => i.InterfaceType.FullName).ToList(),
            ["is_enum"] = t.IsEnum,
            ["is_value_type"] = t.IsValueType,
            ["is_interface"] = t.IsInterface,
            ["attrs"] = Attrs(t),
            ["fields"] = t.Fields.Select(f => new Dictionary<string, object>
            {
                ["name"] = f.Name,
                ["type"] = f.FieldType.FullName,
                ["static"] = f.IsStatic,
                ["literal"] = f.IsLiteral,
                ["constant"] = f.HasConstant ? f.Constant : null,
                ["attrs"] = Attrs(f),
            }).ToList(),
            ["props"] = t.Properties.Select(p => new Dictionary<string, object>
            {
                ["name"] = p.Name,
                ["type"] = p.PropertyType.FullName,
                ["attrs"] = Attrs(p),
            }).ToList(),
            ["methods"] = t.Methods.Select(m => new Dictionary<string, object>
            {
                ["name"] = m.Name,
                ["full"] = m.FullName,
                ["static"] = m.IsStatic,
                ["return"] = m.ReturnType.FullName,
                ["params"] = m.Parameters.Select(p => new Dictionary<string, object> { ["name"] = p.Name, ["type"] = p.ParameterType.FullName }).ToList(),
                ["attrs"] = Attrs(m),
            }).ToList(),
        });
    }
}
File.WriteAllText(outPath, JsonSerializer.Serialize(types, new JsonSerializerOptions { WriteIndented = false, NumberHandling = System.Text.Json.Serialization.JsonNumberHandling.AllowNamedFloatingPointLiterals }));
Console.WriteLine($"{types.Count} types -> {outPath}");
