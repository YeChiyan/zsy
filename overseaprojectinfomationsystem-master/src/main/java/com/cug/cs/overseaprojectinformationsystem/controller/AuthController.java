package com.cug.cs.overseaprojectinformationsystem.controller;


import com.cug.cs.overseaprojectinformationsystem.bean.common.ResData;
import com.cug.cs.overseaprojectinformationsystem.bean.common.ResUtil;
import com.cug.cs.overseaprojectinformationsystem.constant.RoleConstants;
import com.cug.cs.overseaprojectinformationsystem.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthController {

    @GetMapping("hello")
    public String testHello(){
        return "hello";
    }

    @RequestMapping(value = "/login", method = {RequestMethod.GET, RequestMethod.POST})
    public ResData<Map<String, String>> login(@RequestParam String username, @RequestParam String password) {
        ResUtil<Map<String, String>> resUtil = new ResUtil<>();

        String role;
        // 这里简单演示，实际应该查询数据库验证用户名密码和角色
        if ("admin".equals(username) && "123456".equals(password)) {
            role = RoleConstants.ROLE_ADMIN;
        } else if ("user".equals(username) && "123456".equals(password)) {
            role = RoleConstants.ROLE_USER;
        } else {
            return resUtil.setErrorMsg("用户名或密码错误");
        }

        String token = JwtUtil.createToken(username, role);
        Map<String, String> data = new HashMap<>();
        data.put("token", token);
        data.put("role", role);
        return resUtil.setData(data, "登录成功");
    }

    // 需要管理员权限的接口
    @GetMapping("/admin/test")
//    @RequiresRoles(RoleConstants.ROLE_ADMIN)
    public ResData<String> adminTest() {
        log.info("admintest 接口被调用。。。。");
        ResUtil<String> resUtil = new ResUtil<>();
        return resUtil.setData("管理员接口调用成功");
    }

    // 需要用户查看权限的接口
    @GetMapping("/user/view")
    @RequiresPermissions(RoleConstants.PERMISSION_USER_VIEW)
    public ResData<String> userView() {
        ResUtil<String> resUtil = new ResUtil<>();
        return resUtil.setData("用户查看接口调用成功");
    }

    // 需要用户编辑权限的接口
    @GetMapping("/user/edit")
    @RequiresPermissions(RoleConstants.PERMISSION_USER_EDIT)
    public ResData<String> userEdit() {
        ResUtil<String> resUtil = new ResUtil<>();
        return resUtil.setData("用户编辑接口调用成功");
    }
}