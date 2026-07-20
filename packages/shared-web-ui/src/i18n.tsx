import { createContext, useContext } from "react";
import type { ReactNode } from "react";

import type { ExtensionLanguage } from "./extensionSettings";

type TranslationKey =
  | "Private Archive"
  | "Global Search"
  | "Search the archive"
  | "Settings"
  | "Statistics"
  | "Unlock your vault"
  | "Choose a recent vault, then unlock the current selection."
  | "Master Password"
  | "Key File Path"
  | "Unlock Vault"
  | "Unlocking..."
  | "Unlock with Windows Hello"
  | "Manage vaults"
  | "No recent vaults"
  | "Open manager setup to add your first local vault."
  | "Local"
  | "Needs repair in manager"
  | "Extension Settings"
  | "Local extension preferences. These are not stored in the KDBX database."
  | "Save Extension Settings"
  | "Saving..."
  | "Database Settings"
  | "Recent Databases"
  | "Idle Lock Minutes"
  | "Clear Clipboard Seconds"
  | "Language"
  | "VaultKern passkey provider"
  | "Page-load autofill"
  | "Quick Unlock"
  | "Quick Unlock Master Password"
  | "Quick Unlock Key File Path"
  | "Enable Windows Hello"
  | "Enrolling..."
  | "Unlock this vault before enrolling Windows Hello."
  | "Enter the current master credentials once. VaultKern does not retain them after enrollment."
  | "Clipboard clearing writes an empty string after the delay. Browser APIs do not allow reliable background verification that the clipboard still contains the copied secret."
  | "Database"
  | "Loading database settings..."
  | "Back to archive"
  | "Database settings are unavailable."
  | "Save settings"
  | "Database Metadata"
  | "Database Name"
  | "Description"
  | "Default Username"
  | "Public Metadata"
  | "Public Display Name"
  | "Public Color"
  | "Public Icon"
  | "History"
  | "History Items Per Entry"
  | "History Total Size MiB"
  | "Enable recycle bin"
  | "Save And Encryption"
  | "Compression"
  | "Autosave Delay Seconds"
  | "Cipher"
  | "Key Derivation Function"
  | "Transform Rounds"
  | "Argon2 Iterations"
  | "Argon2 Memory MiB"
  | "Argon2 Parallelism"
  | "Credentials"
  | "Change password"
  | "Add password"
  | "Remove password"
  | "New Master Password"
  | "Confirm New Master Password"
  | "Password confirmation does not match."
  | "Saving will remove the current database password."
  | "Groups"
  | "Entries"
  | "New Entry"
  | "Loading entries..."
  | "No entries available."
  | "Unlock a vault to browse entries."
  | "No entries match your search."
  | "Entry Detail"
  | "Modified At"
  | "Select an entry to view details."
  | "Create Entry"
  | "Untitled Entry"
  | "Edit"
  | "Cancel"
  | "Save changes"
  | "Delete Entry"
  | "Title"
  | "Username"
  | "Password"
  | "Show"
  | "Hide"
  | "Show password"
  | "Hide password"
  | "Generate"
  | "Password Generator"
  | "Length"
  | "Uppercase"
  | "Lowercase"
  | "Numbers"
  | "Symbols"
  | "Generated password"
  | "Regenerate"
  | "Use password"
  | "URL"
  | "Notes"
  | "TOTP URI"
  | "Passkey"
  | "No passkey."
  | "Add passkey"
  | "Edit passkey"
  | "Save passkey"
  | "Clear passkey"
  | "Passkey Username"
  | "Credential ID"
  | "Generated User ID"
  | "Private Key PEM"
  | "Relying Party"
  | "User Handle"
  | "Backup eligible"
  | "Backup state"
  | "Additional Properties"
  | "Add property"
  | "No additional properties."
  | "Key"
  | "Value"
  | "Protected"
  | "Remove"
  | "Attachments"
  | "Protect new attachment"
  | "Add attachment"
  | "Add attachment file"
  | "No attachments."
  | "Name"
  | "Replace"
  | "Download"
  | "History Detail"
  | "Back to entries"
  | "Vault Setup"
  | "Add a vault"
  | "Choose where the next vault should come from."
  | "Opening..."
  | "Local File"
  | "Coming soon"
  | "Recent vault records"
  | "OneDrive vaults"
  | "Choose the database file to add."
  | "Current folder"
  | "OneDrive root"
  | "Folder"
  | "Database file"
  | "Open folder"
  | "No database files in this folder."
  | "Unknown size"
  | "This only removes the recent vault record."
  | "Back"
  | "Vault changed on disk. Merged and saved."
  | "Vault changed on disk. Local edits were saved to a conflict copy:"
  | "Vault changed on disk. Local edits were saved as a conflict copy."
  | "Saved to local cache. Remote sync pending."
  | "Using local cache."
  | "Using local cache. Remote sync failed."
  | "Retry sync"
  | "Retrying..."
  | "Remote sync restored."
  | "Failed to retry remote sync"
  | "Database settings saved."
  | "Statistics description"
  | "You have unsaved changes"
  | "Save before leaving this entry, discard your edits, or continue editing."
  | "This entry changed in the current session but is not durable yet. Retry saving before leaving it."
  | "Discard changes"
  | "Continue editing"
  | "Delete this entry permanently?"
  | "This will remove the selected entry from the current vault."
  | "Delete permanently"
  | "Failed to save extension settings"
  | "Failed to update quick unlock"
  | "Failed to add local vault"
  | "Failed to add OneDrive vault"
  | "Failed to save entry changes"
  | "Failed to save entry passkey"
  | "Failed to delete entry"
  | "Failed to download attachment"
  | "Failed to add attachment"
  | "Failed to update attachment"
  | "Failed to replace attachment"
  | "Failed to delete attachment"
  | "Failed to save database settings"
  | "Failed to load entry history"
  | "Failed to load session state"
  | "Failed to load groups"
  | "Failed to load entries"
  | "Failed to load fill candidates"
  | "Failed to load entry detail"
  | "Failed to load database settings"
  | "Failed to unlock vault"
  | "Failed to load popup data"
  | "Failed to load site candidates"
  | "Failed to load record detail"
  | "Current site"
  | "Unlocked"
  | "Locked"
  | "Open Manager"
  | "Lock"
  | "Search"
  | "Search records"
  | "Show less"
  | "Selected record"
  | "Copy"
  | "Copied"
  | "Fill"
  | "Select a record to inspect fields."
  | "No active site"
  | "Suggested for this site";

const ZH_CN: Record<TranslationKey, string> = {
  "Private Archive": "私人档案",
  "Global Search": "全局搜索",
  "Search the archive": "搜索数据库",
  Settings: "设置",
  Statistics: "统计",
  "Unlock your vault": "解锁数据库",
  "Choose a recent vault, then unlock the current selection.": "选择最近数据库，然后解锁当前选择。",
  "Master Password": "主密码",
  "Key File Path": "密钥文件路径",
  "Unlock Vault": "解锁数据库",
  "Unlocking...": "解锁中...",
  "Unlock with Windows Hello": "使用 Windows Hello 解锁",
  "Manage vaults": "管理数据库",
  "No recent vaults": "没有最近数据库",
  "Open manager setup to add your first local vault.": "打开管理器设置并添加第一个本地数据库。",
  Local: "本地",
  "Needs repair in manager": "需要在管理器中修复",
  "Extension Settings": "插件设置",
  "Local extension preferences. These are not stored in the KDBX database.": "本地插件偏好设置，不会保存到 KDBX 数据库。",
  "Save Extension Settings": "保存插件设置",
  "Saving...": "保存中...",
  "Database Settings": "数据库设置",
  "Recent Databases": "最近数据库",
  "Idle Lock Minutes": "闲置锁定分钟数",
  "Clear Clipboard Seconds": "清空剪贴板秒数",
  Language: "语言",
  "VaultKern passkey provider": "VaultKern 通行密钥提供器",
  "Page-load autofill": "页面加载时自动填充",
  "Quick Unlock": "快速解锁",
  "Quick Unlock Master Password": "快速解锁主密码",
  "Quick Unlock Key File Path": "快速解锁密钥文件路径",
  "Enable Windows Hello": "启用 Windows Hello",
  "Enrolling...": "正在注册...",
  "Unlock this vault before enrolling Windows Hello.": "请先解锁此数据库，再注册 Windows Hello。",
  "Enter the current master credentials once. VaultKern does not retain them after enrollment.": "请一次性输入当前主凭据；注册完成后 VaultKern 不会保留它们。",
  "Clipboard clearing writes an empty string after the delay. Browser APIs do not allow reliable background verification that the clipboard still contains the copied secret.": "剪贴板清空会在延迟后写入空字符串。浏览器 API 不允许后台可靠确认剪贴板仍包含刚复制的秘密。",
  Database: "数据库",
  "Loading database settings...": "正在加载数据库设置...",
  "Back to archive": "返回数据库",
  "Database settings are unavailable.": "数据库设置不可用。",
  "Save settings": "保存设置",
  "Database Metadata": "数据库元数据",
  "Database Name": "数据库名称",
  Description: "描述",
  "Default Username": "默认用户名",
  "Public Metadata": "公开元数据",
  "Public Display Name": "公开显示名称",
  "Public Color": "公开颜色",
  "Public Icon": "公开图标",
  History: "历史记录",
  "History Items Per Entry": "每个条目的历史记录数量",
  "History Total Size MiB": "历史记录总大小 MiB",
  "Enable recycle bin": "启用回收站",
  "Save And Encryption": "保存与加密",
  Compression: "压缩",
  "Autosave Delay Seconds": "自动保存延迟秒数",
  Cipher: "加密算法",
  "Key Derivation Function": "密钥派生函数",
  "Transform Rounds": "转换次数",
  "Argon2 Iterations": "Argon2 迭代次数",
  "Argon2 Memory MiB": "Argon2 内存 MiB",
  "Argon2 Parallelism": "Argon2 并行度",
  Credentials: "凭据",
  "Change password": "更改密码",
  "Add password": "添加密码",
  "Remove password": "删除密码",
  "New Master Password": "新主密码",
  "Confirm New Master Password": "确认新主密码",
  "Password confirmation does not match.": "两次输入的密码不一致。",
  "Saving will remove the current database password.": "保存后将删除当前数据库密码。",
  Groups: "分组",
  Entries: "条目",
  "New Entry": "新建条目",
  "Loading entries...": "正在加载条目...",
  "No entries available.": "没有可用条目。",
  "Unlock a vault to browse entries.": "解锁数据库以浏览条目。",
  "No entries match your search.": "没有条目匹配搜索。",
  "Entry Detail": "条目详情",
  "Modified At": "更新时间",
  "Select an entry to view details.": "选择一个条目查看详情。",
  "Create Entry": "创建条目",
  "Untitled Entry": "未命名条目",
  Edit: "编辑",
  Cancel: "取消",
  "Save changes": "保存更改",
  "Delete Entry": "删除条目",
  Title: "标题",
  Username: "用户名",
  Password: "密码",
  Show: "显示",
  Hide: "隐藏",
  "Show password": "显示密码",
  "Hide password": "隐藏密码",
  Generate: "生成",
  "Password Generator": "密码生成器",
  Length: "长度",
  Uppercase: "大写字母",
  Lowercase: "小写字母",
  Numbers: "数字",
  Symbols: "符号",
  "Generated password": "生成的密码",
  Regenerate: "重新生成",
  "Use password": "使用密码",
  URL: "URL",
  Notes: "备注",
  "TOTP URI": "TOTP URI",
  Passkey: "Passkey",
  "No passkey.": "没有 Passkey。",
  "Add passkey": "添加 Passkey",
  "Edit passkey": "编辑 Passkey",
  "Save passkey": "保存 Passkey",
  "Clear passkey": "清除 Passkey",
  "Passkey Username": "Passkey 用户名",
  "Credential ID": "凭据 ID",
  "Generated User ID": "生成的用户 ID",
  "Private Key PEM": "私钥 PEM",
  "Relying Party": "依赖方",
  "User Handle": "用户句柄",
  "Backup eligible": "可备份",
  "Backup state": "已备份",
  "Additional Properties": "附加属性",
  "Add property": "添加属性",
  "No additional properties.": "没有附加属性。",
  Key: "键",
  Value: "值",
  Protected: "受保护",
  Remove: "移除",
  Attachments: "附件",
  "Protect new attachment": "保护新附件",
  "Add attachment": "添加附件",
  "Add attachment file": "添加附件文件",
  "No attachments.": "没有附件。",
  Name: "名称",
  Replace: "替换",
  Download: "下载",
  "History Detail": "历史详情",
  "Back to entries": "返回条目",
  "Vault Setup": "数据库设置向导",
  "Add a vault": "添加数据库",
  "Choose where the next vault should come from.": "选择数据库来源。",
  "Opening...": "正在打开...",
  "Local File": "本地文件",
  "Coming soon": "即将支持",
  "Recent vault records": "最近数据库记录",
  "OneDrive vaults": "OneDrive 数据库",
  "Choose the database file to add.": "选择要添加的数据库文件。",
  "Current folder": "当前文件夹",
  "OneDrive root": "OneDrive 根目录",
  Folder: "文件夹",
  "Database file": "数据库文件",
  "Open folder": "打开文件夹",
  "No database files in this folder.": "当前文件夹没有可选数据库文件。",
  "Unknown size": "未知大小",
  "This only removes the recent vault record.": "这只会移除最近数据库记录。",
  Back: "返回",
  "Vault changed on disk. Merged and saved.": "数据库文件已在磁盘上变化，已合并并保存。",
  "Vault changed on disk. Local edits were saved to a conflict copy:": "数据库文件已在磁盘上变化，本地编辑已保存到冲突副本：",
  "Vault changed on disk. Local edits were saved as a conflict copy.": "数据库文件已在磁盘上变化，本地编辑已保存为冲突副本。",
  "Saved to local cache. Remote sync pending.": "已保存到本地缓存，等待远程同步。",
  "Using local cache.": "正在使用本地缓存。",
  "Using local cache. Remote sync failed.": "正在使用本地缓存，远程同步失败。",
  "Retry sync": "重试同步",
  "Retrying...": "正在重试...",
  "Remote sync restored.": "远程同步已恢复。",
  "Failed to retry remote sync": "重试远程同步失败",
  "Database settings saved.": "数据库设置已保存。",
  "Statistics description": "数据库统计会在分析功能接入共享管理器后显示。",
  "You have unsaved changes": "有未保存的更改",
  "Save before leaving this entry, discard your edits, or continue editing.": "离开条目前保存、丢弃更改，或继续编辑。",
  "This entry changed in the current session but is not durable yet. Retry saving before leaving it.": "条目已在当前会话中更改，但尚未持久保存。请在离开前重试保存。",
  "Discard changes": "丢弃更改",
  "Continue editing": "继续编辑",
  "Delete this entry permanently?": "永久删除此条目？",
  "This will remove the selected entry from the current vault.": "这会从当前数据库中删除选中的条目。",
  "Delete permanently": "永久删除",
  "Failed to save extension settings": "保存插件设置失败",
  "Failed to update quick unlock": "更新快速解锁失败",
  "Failed to add local vault": "添加本地数据库失败",
  "Failed to add OneDrive vault": "添加 OneDrive 数据库失败",
  "Failed to save entry changes": "保存条目更改失败",
  "Failed to save entry passkey": "保存条目 Passkey 失败",
  "Failed to delete entry": "删除条目失败",
  "Failed to download attachment": "下载附件失败",
  "Failed to add attachment": "添加附件失败",
  "Failed to update attachment": "更新附件失败",
  "Failed to replace attachment": "替换附件失败",
  "Failed to delete attachment": "删除附件失败",
  "Failed to save database settings": "保存数据库设置失败",
  "Failed to load entry history": "加载条目历史失败",
  "Failed to load session state": "加载会话状态失败",
  "Failed to load groups": "加载分组失败",
  "Failed to load entries": "加载条目失败",
  "Failed to load fill candidates": "加载填充候选失败",
  "Failed to load entry detail": "加载条目详情失败",
  "Failed to load database settings": "加载数据库设置失败",
  "Failed to unlock vault": "解锁数据库失败",
  "Failed to load popup data": "加载弹窗数据失败",
  "Failed to load site candidates": "加载站点候选失败",
  "Failed to load record detail": "加载记录详情失败",
  "Current site": "当前站点",
  Unlocked: "已解锁",
  Locked: "已锁定",
  "Open Manager": "打开管理器",
  Lock: "锁定",
  Search: "搜索",
  "Search records": "搜索记录",
  "Show less": "收起",
  "Selected record": "选中记录",
  Copy: "复制",
  Copied: "已复制",
  Fill: "填充",
  "Select a record to inspect fields.": "选择记录以查看字段。",
  "No active site": "没有活动站点",
  "Suggested for this site": "当前站点建议"
};

const I18nContext = createContext<ExtensionLanguage>("en");

export function I18nProvider({
  language,
  children
}: {
  language: ExtensionLanguage;
  children: ReactNode;
}) {
  return <I18nContext.Provider value={language}>{children}</I18nContext.Provider>;
}

export function useText() {
  const language = useContext(I18nContext);
  return (key: TranslationKey) => (language === "zh-CN" ? ZH_CN[key] : key);
}

export function useLanguage() {
  return useContext(I18nContext);
}

export function translate(language: ExtensionLanguage, key: TranslationKey) {
  return language === "zh-CN" ? ZH_CN[key] : key;
}

export function showMoreText(language: ExtensionLanguage, count: number) {
  return language === "zh-CN" ? `再显示 ${count} 个` : `Show ${count} more`;
}

export function removeRecordLabel(language: ExtensionLanguage, name: string) {
  return language === "zh-CN" ? `移除 ${name} 记录` : `Remove ${name} record`;
}

export function deleteEntryDescription(language: ExtensionLanguage, title: string) {
  return language === "zh-CN"
    ? `这会从当前数据库中删除 ${title}。`
    : `This will remove ${title} from the current vault.`;
}
