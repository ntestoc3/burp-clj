# Change Log
All notable changes to this project will be documented in this file. This change log follows the conventions of [keepachangelog.com](http://keepachangelog.com/).

## 0.5.3 

## 0.5.2 - 2021-02-14
### Changed 
- burp-clj.utils中->bytes,->string转换默认编码改为ISO-8859-1,防止相互转换造成符号位丢失。

### Fixed
- burp-clj.utils中burp-img在burp v2021.2中找不到资源的错误

## 0.5.1 - 2020-12-26
### Fixed
- 修复filter-exp regex参数错误

## 0.5.0 - 2020-12-26
### Added
- message-editor增加make-syntax-editor-tab函数,用于创建使用syntax-editor的IMessageEditorTab

### Fixed 
- 修复ui input-dir默认目录显示的问题
- 修复utils中->bytes,->string转换的编码问题，默认使用ASCII,防止互转时数据改变

### Changed 
- butp-clj.utils命名空间下http消息处理的函数全部转移到burp-clj.http-message命名空间中
- parse-request, parse-response返回body类型改为bytes,防止编码转换

## 0.4.15 - 2020-12-09
## Fixed
- 修复i18n, get-language初始化可能为空的异常

## 0.4.14 - 2020-12-08

### Added
- 添加core.async依赖

### Fixed 
- 修复script table第一行鼠标点击不起作用
- 修复defsetting初始化错误


## 0.4.13 - 2020-12-01
### Added
- utils添加conform-dlg函数

### Fixed
- 插件卸载时调用shutdown-agents,防止线程没退出
- 依赖seesaw新版本，修复table显示的异常

## 0.4.12 - 2020-11-30
### Added
- issue添加add-issue!函数
- table-util添加values-by函数

### Fixed
- 重复加载相同的脚本,script-table处理错误的问题(无法区分是用户点击还是代码修改table model数据)

### Changed
- table-util insert-by!找不到条件就新增行

## 0.4.11 - 2020-11-30
### Added
- 添加i18n支持

### Fixed
- 卸载插件时script-table调用switch-clojure-plugin-tab造成异常

### Changed
- 把clojure中的修补代码放到java中调用,在burp-clj.core调用之前执行


## 0.4.10 - 2020-11-29 
### Fixed 
- 修改主界面脚本加载时表格异常的提问

### Added 
- 主界面add scripts source对话框中增加选择文件夹按钮
- 添加CHANGELOG

## 0.4.9 - 2020-11-28 
### Fixed
- 解决向message viewer table中添加数据异常的问题
- 解决message viewer table行中颜色设置错误的问题

## 0.4.8 - 2020-11-27
### Fixed
- 解决burp collaborator界面的定时器问题

## 0.4.7 - 2020-11-26
### Added
- 添加burp collaborator界面

[0.1.1]: https://github.com/your-name/burp-clj/compare/0.1.0...0.1.1
