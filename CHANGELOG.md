# Change Log
All notable changes to this project will be documented in this file. This change log follows the conventions of [keepachangelog.com](http://keepachangelog.com/).

## 0.4.12 - 2020-11-30
### Added
- add-issue!函数

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
