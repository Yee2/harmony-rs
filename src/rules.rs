use std::collections::HashMap;

use log::{info, warn};
use serde::{Deserialize, Serialize};

use crate::prelude::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct Rules(HashMap<String, Option<Rules>>);

#[inline]
fn is_valid_domain(parts: &Vec<&str>) -> bool {
    for part in parts {
        if part.len() < 1 || part.len() > 63 { // 每个部分的长度必须在 1 到 63 之间
            return false;
        }
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') { // 每个部分只能包含字母、数字和连字符
            return false;
        }
        if part.starts_with('-') || part.ends_with('-') { // 每个部分不能以连字符开头或结尾
            return false;
        }
    }
    let tld = parts.last().unwrap(); // 获取顶级域名
    if tld.len() < 2 || tld.len() > 63 { // 顶级域名的长度必须在 2 到 63 之间
        return false;
    }
    if !tld.chars().all(|c| c.is_ascii_alphabetic()) { // 顶级域名只能包含字母
        return false;
    }
    true // 如果所有条件都符合，则返回 true
}


impl Rules {
    pub fn new() -> Rules {
        Rules(HashMap::new())
    }
    pub fn from_file(filename: &str) -> Result<Rules> {
        let file = std::fs::File::open(filename)?;
        let rules: Rules = serde_json::from_reader(file)?;
        return Ok(rules);
    }
    pub fn add(&mut self, domain: &str) {
        let domain = domain.trim().trim_end_matches(".");
        if domain.len() > 255 {
            warn!("invalid hostname: {}",domain);
            return;
        }
        let mut list: Vec<&str> = domain.split(".").collect();
        if !is_valid_domain(&list) {
            warn!("invalid hostname: {}",domain);
            return;
        }
        if list.len() > 0 {
            info!("add proxy domain: {}",domain);
            self.push(list);
        }
    }
    fn push(&mut self, mut list: Vec<&str>) {
        let Some(k) = list.pop() else { return; };
        if list.len() == 0 && self.0.contains_key(k) {// 这已经是最后一个元素
            self.0.insert(String::from(k), None);
            return;
        }
        if let Some(mut m) = self.0.get_mut(k) {
            if let Some(r) = m.as_mut() {
                r.push(list);
            }
            // 如果存在某个 key ，但是这个 key 下面为空 None，那么表示其后面所有子域名都匹配上。
            // 这时候，子域名不需要做插入处理
        } else if list.len() > 0 {
            let mut r = Rules(HashMap::new());
            r.push(list);
            self.0.insert(String::from(k), Some(r));
        } else {
            self.0.insert(String::from(k), None);
        }
    }
    pub fn contain(&self, target: &str) -> bool {
        if target.trim_end_matches(".").ends_with(".cn") {
            return false;
        }
        let layers: Vec<&str> = target.trim_end_matches(".").split(".").collect();
        let mut current: &HashMap<String, Option<Rules>> = &self.0;
        for p in layers.iter().rev() {
            match current.get(*p) {
                Some(next) => {
                    match next {
                        Some(rules) => {
                            current = &rules.0
                        }
                        None => {
                            return true;
                        }
                    }
                }
                None => {
                    return false;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod test {
    use crate::rules::Rules;

    #[test]
    fn test_rule() {

        // 1. 测试 Rules::new() 函数是否能够成功创建一个空的 Rules 对象。

        let rules = Rules::new();
        assert_eq!(rules.0.len(), 0);

        // 2. 测试 Rules::from_file() 函数是否能够成功从文件中读取规则。

        let rules = Rules::from_file("rules.json").unwrap();
        assert_eq!(rules.contain("www.google.com"), true);
        assert_eq!(rules.contain("www.baidu.com"), false);

        // 3. 测试 Rules::add() 函数是否能够成功添加一个域名规则。

        let mut rules = Rules::new();
        rules.add("www.google.com");
        assert_eq!(rules.0.len(), 1);
        assert_eq!(rules.contain("www.google.com"), true);

        // 4. 测试 Rules::add() 函数是否能够正确处理无效的域名。

        let mut rules = Rules::new();
        rules.add("www.google.com.");
        assert_eq!(rules.0.len(), 1);
        rules.add("www.google.com.invalid");
        assert_eq!(rules.0.len(), 2);

        // 5. 测试 Rules::contain() 函数是否能够正确判断一个域名是否在规则中。

        let mut rules = Rules::new();
        rules.add("www.google.com");
        assert_eq!(rules.contain("www.google.com"), true);
        assert_eq!(rules.contain("www.www.google.com"), true);
        assert_eq!(rules.contain("www.baidu.com"), false);
        assert_eq!(rules.contain("google.com"), false);
        assert_eq!(rules.contain("www.google.com.cn"), false);

        rules.add("com");
        assert_eq!(rules.contain("com"), true);
        assert_eq!(rules.contain("cn"), false);
        assert_eq!(rules.0.len(), 1);
    }
}
