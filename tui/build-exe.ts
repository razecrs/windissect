// Compiles the TUI into one standalone executable with Bun, so a release
// needs no Node.js or node_modules: `bun build-exe.ts <bun-target> <outfile>`,
// e.g. `bun build-exe.ts bun-windows-x64 ../target/tui-exe/windissect-tui.exe`.
//
// Ink imports react-devtools-core for its DEV=true devtools hook. The package
// isn't a dependency, and a compiled binary can't resolve it at run time, so
// an empty stub stands in for it.
const [target = 'bun-windows-x64', outfile = '../target/tui-exe/windissect-tui.exe'] = Bun.argv.slice(2);

const noDevtools: import('bun').BunPlugin = {
  name: 'no-react-devtools',
  setup(build) {
    build.onResolve({filter: /^react-devtools-core$/}, () => ({path: 'react-devtools-core', namespace: 'stub'}));
    build.onLoad({filter: /.*/, namespace: 'stub'}, () => ({
      contents: 'export default {initialize() {}, connectToDevTools() {}};',
      loader: 'js',
    }));
  },
};

const result = await Bun.build({
  entrypoints: ['src/index.tsx'],
  compile: {target: target as import('bun').Build.Target, outfile},
  minify: true,
  define: {'process.env.DEV': '"false"'},
  plugins: [noDevtools],
});
if (!result.success) {
  for (const log of result.logs) console.error(log);
  process.exit(1);
}
console.log(`compiled ${outfile} for ${target}`);
