import std.file;
import std.path;
import std.process;
import std.stdio;

const srcFiles = [
	"src/argon2.c",
	"src/core.c",
	"src/encoding.c",
	"src/opt.c",
	"src/thread.c",
	"src/blake2/blake2b.c",
];

// Set when building object files.
auto objFiles = new string[srcFiles.length];

struct Settings
{
	string argon2Dir = "argon2";
	string buildDir = "";
	string libDir = "libs";

	int exitCode = 0;
	bool exit = false;
}

private void removeIfExists(string file, bool print = true)
{
	if (exists(file) && isFile(file))
	{
		if (print)
			writeln("Remove existing file: ", file);
		remove(file);
	}
}

void parseArgs(string[] args, ref Settings settings)
{
	import std.getopt;

	// dfmt off
	auto ops = getopt(
		args,
		"argon2-dir|a", "Argon2 reference implementation project root dir. Defaults to ./argon2", &settings.argon2Dir,
		"build-dir|b", "Directory to place obj files in. Defaults to <argon2-dir>/build", &settings.buildDir,
		"lib-dir|l", "Directory to place static library in. Defaults to ./libs", &settings.libDir,
	);
	// dfmt on

	if (ops.helpWanted)
	{
		defaultGetoptFormatter(
			stdout.lockingTextWriter(),
			"Helper script to build argon2 library with msvc toolchain (cl, lib)\n",
			ops.options,
			"%-*s, %-*s  %-*s%s\n");

		settings.exit = true;
		return;
	}

	if (settings.buildDir == "")
	{
		settings.buildDir = buildNormalizedPath("argon2", "build");
	}
}

int buildObjFiles(Settings settings)
{
	const argon2Dir = settings.argon2Dir;
	const buildDir = settings.buildDir;
	const baseCommand = [
		"cl", "-c", "-O2",
		"-I" ~ buildNormalizedPath(argon2Dir, "include")
	];

	mkdirRecurse(buildDir);

	foreach (i, sourceFile; srcFiles)
	{
		const srcWithPath = buildNormalizedPath(argon2Dir, sourceFile);

		const objName = sourceFile.baseName.setExtension(".obj");
		const targetObjFile = buildNormalizedPath(buildDir, objName);
		objFiles[i] = targetObjFile;

		const commandSpecification = [
			srcWithPath,
			"-Fo:" ~ targetObjFile,
		];

		const command = baseCommand ~ commandSpecification;

		removeIfExists(targetObjFile);

		writefln("%-(%s %)", command);
		auto res = execute(command);
		if (res.status != 0)
		{
			writeln(res.output);
			return res.status;
		}
	}
	return 0;
}

int buildArgon2Lib(Settings settings)
{
	const libPath = settings.libDir;
	const targetLibFile = buildNormalizedPath(libPath ~ "/", "argon2.lib");
	const baseCommand = ["lib",
		"/OUT:" ~ targetLibFile];

	mkdirRecurse(libPath);
	removeIfExists(targetLibFile);

	const command = baseCommand ~ objFiles;
	writefln("%-(%s %)", command);
	auto res = execute(command);

	if (res.status != 0)
		writeln(res.output);
	return res.status;
}

int run(string[] args)
{
	Settings settings;
	parseArgs(args, settings);
	if (settings.exit)
		return settings.exitCode;

	if (auto returnValue = buildObjFiles(settings))
		return returnValue;

	writeln();

	if (auto returnValue = buildArgon2Lib(settings))
		return returnValue;

	return 0;
}

int main(string[] args)
{
	try
	{
		return run(args);
	}
	catch (Exception e)
	{
		try
		{
			version (Debug)
			{
				writeln(e);
			}
			else
			{
				writeln(e.msg);
			}
		}
		catch (Exception _)
		{
		}
	}
	return -1;
}
