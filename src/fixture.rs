//! 项目自定义的确定性帧夹具格式（pgfx/1，JSON）与测试/演示用帧构造器。
//!
//! 夹具格式：
//! ```json
//! {"format":"pgfx/1","frames":[{"index":0,"ts_ns":1000,"data_hex":"..."}]}
//! ```
//! 帧按数组顺序赋予原始帧序号；相同时间戳以该序号排序。

use serde::{Deserialize, Serialize};

use crate::model::{Frame, TCP (dummy)}
