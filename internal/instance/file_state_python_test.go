package instance

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The ordinary test uses Cowrie's positional nodes and copy-on-write contract.
// QPOT_TEST_COWRIE_SOURCE additionally runs the same sequences with the exact
// image's unmodified shell/fs.py, including its real copy/rename/chmod/read code.
// Only config, resource bytes and Twisted logging are replaced in that mode.
const cowrieFileStateHarness = `
import copy, hashlib, importlib.util, json, pathlib, posixpath, stat, sys, types

core_path, ls_path, source = sys.argv[1:]
def module(name):
    if name not in sys.modules:
        mod = sys.modules[name] = types.ModuleType(name)
        mod.__path__ = []
        parent, _, child = name.rpartition('.')
        if parent:
            setattr(module(parent), child, mod)
    return sys.modules[name]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    parent, _, child = name.rpartition('.')
    setattr(module(parent), child, mod)
    spec.loader.exec_module(mod)
    return mod
class Logger:
    def __getattr__(self, key): return lambda *a, **k: None
class Config:
    @staticmethod
    def get(section, key, fallback=None): return fallback
module('twisted.logger').Logger = Logger
module('cowrie.core.config').CowrieConfig = Config
module('cowrie.shell.command').HoneyPotCommand = type('HoneyPotCommand', (), {})
module('cowrie.shell.pipe').PipeProtocol = type('PipeProtocol', (), {})
module('cowrie.core.qpot_bait')._identity = lambda: (1700000000, 1700100000)
class OriginalPasswd:
    def getpwuid(self, uid): return {'pw_name': {0:'root',1000:'debian'}[uid]}
class OriginalGroup:
    def getgrgid(self, gid): return {'gr_name': {0:'root',1000:'debian'}[gid]}
module('cowrie.shell.pwd').Passwd = OriginalPasswd
module('cowrie.shell.pwd').Group = OriginalGroup
fsmod = module('cowrie.shell.fs')
for i, key in enumerate(('A_NAME','A_TYPE','A_UID','A_GID','A_SIZE','A_MODE','A_CTIME','A_CONTENTS','A_TARGET','A_REALFILE')):
    setattr(fsmod, key, i)
for i, key in enumerate(('T_LINK','T_DIR','T_FILE','T_BLK','T_CHR','T_SOCK','T_FIFO')):
    setattr(fsmod, key, i)
HEADER = b'\x7fELF\x02\x01fixture-architecture-header'
def file(name, data=b'payload\n', mode=0o100644, uid=1000, gid=1000):
    return [name, 2, uid, gid, len(data), mode, 1710000000, data, None, None]
def directory(name, children):
    return [name, 1, 0, 0, 4096, 0o40755, 1690000000, children, None, None]
base = directory('/', [directory('srv', [file('report'), file('copy'), file('node-1148'), file('node-2870')]),
    directory('etc', [file('passwd', b'root:x:0:0:root:/root:/bin/bash\ndebian:x:1000:1000::/home/debian:/bin/bash\n'),
                      file('group', b'root:x:0:\ndebian:x:1000:\n')]),
    directory('usr', [directory('bin', [['tool', 2, 0, 0, 4096, 0o100755, 1690000000, [], None, None]])])])
pristine = copy.deepcopy(base)

class FixtureFS:
    def __init__(self):
        self.fs, self._private_fs, self.generated_files = base, False, {}
    def _ensure_private_fs(self):
        if not self._private_fs:
            self.fs = copy.deepcopy(self.fs)
            self._private_fs = True
    def resolve_path(self, path, cwd): return posixpath.normpath(posixpath.join(cwd, path))
    def getfile(self, path, follow_symlinks=True):
        node = self.fs
        for part in path.strip('/').split('/') if path.strip('/') else []:
            node = next((c for c in node[7] if c[0] == part), None)
            if node is None: return None
        return node
    def exists(self, path): return self.getfile(path) is not None
    def isdir(self, path): return self.getfile(path)[1] == 1
    def file_contents(self, path):
        n = self.getfile(path)
        return n[7] if isinstance(n[7], bytes) else HEADER
    def mkfile(self, path, uid, gid, size, mode):
        self._ensure_private_fs()
        self.getfile(posixpath.dirname(path))[7].append(file(posixpath.basename(path), b'', mode, uid, gid))
    def rename(self, oldpath, newpath):
        self._ensure_private_fs()
        node = self.getfile(oldpath)
        self.getfile(posixpath.dirname(oldpath))[7].remove(node)
        node[0] = posixpath.basename(newpath)
        self.getfile(posixpath.dirname(newpath))[7].append(node)
    def chmod(self, path, mode):
        self._ensure_private_fs()
        n = self.getfile(path); n[5] = stat.S_IFMT(n[5]) | mode
    def chown(self, path, uid, gid):
        self._ensure_private_fs()
        n = self.getfile(path); n[2], n[3] = uid, gid
    def utime(self, path, atime, mtime):
        self._ensure_private_fs(); self.getfile(path)[6] = mtime

if source:
    source = pathlib.Path(source)
    module('cowrie.core.honeyfs').get_tree = lambda: base
    module('cowrie.core.artifact').temp_download_path = lambda name: '/unused-by-this-test'
    module('cowrie.core.resources').read_data_bytes = lambda *args: HEADER
    fsmod = load('cowrie.shell.fs', source / 'shell/fs.py')
    tree = fsmod.HoneyPotFilesystem('linux-x64', '/home/debian')
else:
    tree = FixtureFS()
core = load('cowrie.commands.coreutils', core_path)
listing = load('cowrie.commands.ls', ls_path)
now = [1720000000.25]
core.time.time = lambda: now[0]
protocol = types.SimpleNamespace(fs=tree, hostname='web01')
state = core.qpot_track_files(protocol) if hasattr(core, 'qpot_track_files') else None
if state is not None:
    assert state is core.qpot_track_files(protocol)
assert tree.fs is base and not tree._private_fs, 'tracking must not copy read-only trees'
cmd = core.Command_stat.__new__(core.Command_stat)
cmd.protocol, cmd.fs = protocol, tree
cmd.qpot_root, cmd.qpot_installed = (8,1), 1700000000
cmd.qpot_busybox, cmd.qpot_version = False, (9,1)
def value(letter, path):
    return cmd.qpot_value(letter, path, path, tree.getfile(path), False)
inode = value('i', '/srv/report')
times = cmd.qpot_times('/srv/report', tree.getfile('/srv/report'))
assert value('i','/srv/node-1148') != value('i','/srv/node-2870'), 'distinct files share an inode'
tree.mkfile('/srv/unrelated', 0, 0, 0, 0o100644)
assert tree.fs is not base and tree._private_fs
assert value('i', '/srv/report') == inode, 'unrelated first COW write changed inode'
assert cmd.qpot_times('/srv/report', tree.getfile('/srv/report')) == times
now[0] += 10
tree.rename('/srv/report', '/srv/renamed')
assert value('i', '/srv/renamed') == inode, 'rename changed inode'
renamed = cmd.qpot_times('/srv/renamed', tree.getfile('/srv/renamed'))
assert renamed[1] == times[1] and renamed[3] == times[3], 'rename changed mtime/birth'
assert renamed[2] == now[0], 'rename did not update change time'
protocol.hostname = 'changed01'
assert value('i', '/srv/renamed') == inode
assert cmd.qpot_times('/srv/renamed', tree.getfile('/srv/renamed')) == renamed
now[0] += 10
tree.chmod('/srv/renamed', 0o600)
assert value('a', '/srv/renamed') == '600'
assert cmd.qpot_times('/srv/renamed', tree.getfile('/srv/renamed')) == (renamed[0], renamed[1], now[0], renamed[3])
now[0] += 10
tree.chown('/srv/renamed', 2001, 2001)
assert value('u', '/srv/renamed') == 2001
assert value('g', '/srv/renamed') == 2001
assert cmd.qpot_times('/srv/renamed', tree.getfile('/srv/renamed'))[2] == now[0]
now[0] += 10
tree.utime('/srv/renamed', 1600000000, 1600000010)
assert cmd.qpot_times('/srv/renamed', tree.getfile('/srv/renamed')) == (1600000000,1600000010,now[0],renamed[3])
now[0] += 10
tree.chmod('/srv/copy', 0o600)
assert cmd.qpot_times('/srv/copy', tree.getfile('/srv/copy'))[2] == now[0], 'first stat missed prior chmod'
tree.getfile('/etc/passwd')[7] += b'analyst:x:2001:2001::/home/analyst:/bin/bash\n'
tree.getfile('/etc/group')[7] += b'analyst:x:2001:\n'
# Invalid operator/attacker edits must not break a later ls/stat name lookup.
tree.getfile('/etc/passwd')[7] += b'bad:x:' + b'9'*5000 + b':0::/:/bin/bash\n'
tree.getfile('/etc/group')[7] += b'overflow:x:4294967295:\n# comment:x:2001:\n'
ls = listing.Command_ls.__new__(listing.Command_ls); ls.fs = tree
assert ls.uid2name(2001) == 'analyst' and ls.gid2name(2001) == 'analyst'
assert core.qpot_id_names(tree, '/etc/passwd')[2001] == ls.uid2name(2001)
assert ls.uid2name(4444) == '4444' and ls.gid2name(4444) == '4444'
summer = core.QpotSum.__new__(core.QpotSum)
summer.fs, summer.protocol, summer.cwd = tree, protocol, '/'
summer.errorWrite = lambda message: (_ for _ in ()).throw(AssertionError(message))
data = summer.contents('/usr/bin/tool', 'sha256sum')
assert data == tree.file_contents('/usr/bin/tool') == HEADER
digest = hashlib.sha256(data).hexdigest()
protocol.hostname = 'another-name'
tree.rename('/usr/bin/tool', '/usr/bin/moved-tool')
assert hashlib.sha256(summer.contents('/usr/bin/moved-tool','sha256sum')).hexdigest() == digest
assert hashlib.sha256(tree.file_contents('/usr/bin/moved-tool')).hexdigest() == digest
assert base == pristine, 'a session mutated the shared persona tree'
last_times = cmd.qpot_times('/srv/renamed', tree.getfile('/srv/renamed'))
try:
    tree.chmod('/srv/missing', 0o600)
except (OSError, TypeError):
    pass
else:
    raise AssertionError('missing chmod unexpectedly succeeded')
assert cmd.qpot_times('/srv/renamed', tree.getfile('/srv/renamed')) == last_times
other = fsmod.HoneyPotFilesystem('linux-x64', '/home/debian') if source else FixtureFS()
other_protocol = types.SimpleNamespace(fs=other, hostname='web01')
other_state = core.qpot_track_files(other_protocol)
other_cmd = core.Command_stat.__new__(core.Command_stat)
other_cmd.protocol, other_cmd.fs = other_protocol, other
other_cmd.qpot_root, other_cmd.qpot_installed = (8,1), 1700000000
other_cmd.qpot_busybox, other_cmd.qpot_version = False, (9,1)
assert other_state is not state and other.fs is base
assert other_cmd.qpot_value('i','/srv/report','/srv/report',other.getfile('/srv/report'),False) == inode
assert other.file_contents('/etc/passwd') == pristine[7][1][7][0][7]
hostname = core.Command_hostname.__new__(core.Command_hostname)
hostname.user, hostname.protocol = {'uid':1000,'gid':1000}, protocol
hostname.pp = types.SimpleNamespace(tpot_sudo=False)
hostname.errorWrite = lambda message: None
unchanged = protocol.hostname
assert hostname.set_name('denied-name') == 1 and protocol.hostname == unchanged
hostname.pp.tpot_sudo = True
assert hostname.set_name('maintenance01') == 0 and protocol.hostname == 'maintenance01'
assert hostname.user['uid'] == 1000, 'sudo changed the login identity'
hostname.pp.tpot_sudo = False
assert hostname.set_name('denied-again') == 1 and protocol.hostname == 'maintenance01'
print(json.dumps({'mode':'pinned-fs' if source else 'node-fixture','result':'PASS',
                  'source_sha256':hashlib.sha256((source/'shell/fs.py').read_bytes()).hexdigest() if source else None}))
`

func TestCowrieFileIdentitySequences(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string][]byte{
		"coreutils.py": cowrieCoreutilsPy,
		"ls.py":        cowrieLsPy,
		"sequence.py":  []byte(cowrieFileStateHarness),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sources := []string{""}
	if source := os.Getenv("QPOT_TEST_COWRIE_SOURCE"); source != "" {
		sources = append(sources, source)
	}
	for _, source := range sources {
		cmd := exec.Command(python(t), "-I", filepath.Join(dir, "sequence.py"), filepath.Join(dir, "coreutils.py"),
			filepath.Join(dir, "ls.py"), source)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("file state sequence (source %q): %v\n%s", source, err, output)
		} else {
			t.Logf("%s", output)
		}
	}
}
