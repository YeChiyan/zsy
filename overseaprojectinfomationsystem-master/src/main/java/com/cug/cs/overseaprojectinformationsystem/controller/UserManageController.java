package com.cug.cs.overseaprojectinformationsystem.cotroller;

import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseData;
import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseUtil;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.Member;
import com.cug.cs.overseaprojectinformationsystem.service.CenterManageService;
import com.cug.cs.overseaprojectinformationsystem.service.UserManageService;
import com.cug.cs.overseaprojectinformationsystem.util.jwt.JwtTokenUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.DigestUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * @description: TODO 主要是用户管理 分中心管理 超级管理员
 * @author: ShengHui
 * @date: 2023-09-16  00:04
 */
@Slf4j
@RestController
@RequestMapping("market/manage")
public class UserManageController {
    
    @Autowired
    UserManageService userManageService;
    @Autowired
    CenterManageService centerManageService;
    
    @RequiresPermissions("market:manege:user")
    @GetMapping("/user/{id}")
    public ResponseData getUserInfoByUserId(HttpServletRequest request, @PathVariable Integer id) {
        Member userInfo=userManageService.selectUserInfoByUserId(id);
        
        ResponseData<Member> userResponseData = new ResponseData<Member>();
        userResponseData.setSuccess(true);
        userResponseData.setCode(200);
        userResponseData.setResult(userInfo);
        userResponseData.setMessage("成功获取用户个人信息");
        return userResponseData;
    }
    
    @RequiresPermissions("market:manage:user:create")
    @PostMapping("/user/create")
    public ResponseData createUser(@RequestBody Member member) {
        //  确定分中心是否创建
        boolean flag = centerManageService.selectCenterExistsByCenterId(member.getCenterId());
        if (flag) {
            return new ResponseUtil().setErrorMsg(400, "该分中心不存在，请先创建分中心");
        }
        if (member.getRoleId() == null || member.getRoleId()[0] == 0) {
            Integer[] integers = new Integer[1];
            integers[0]=3;
            member.setRoleId(integers);
        }
        member.setDeleted(true);
        boolean result= userManageService.createNewUser(member);
        return new ResponseUtil<>().setData(true, "用户创建成功");
    }
    
    @RequiresPermissions("market:manage:user:list")
    @GetMapping("/user/list/{centerId}")
    public ResponseData selectUserList(HttpServletRequest request,@PathVariable String centerId) {
        if (centerId == null || centerId.equals("")) {
            List<Member> memberList=userManageService.selectUserListByCenterId(centerId);
        }
        List<Member> memberList=userManageService.selectUserList();
    
        return new ResponseUtil().setData(memberList,"获取到所有用户");
    }
    
    /**
     * @description: 模糊查询所有用户（待定，前端处理？）
     * @param:
     * @return:
     */
   /* @RequiresPermissions("market:manage:user:search")
    @GetMapping*/
    /**
     * @description: 修改用户信息
     * @param:
     * @return:
     */
    @RequiresPermissions("market:manage:user:update")
    @PutMapping("/user/update")
    public ResponseData updateUserInfo(@RequestBody Member member) {
        boolean flag=userManageService.updateUserInfo(member);
        if (flag) {
            return new ResponseUtil().setData(true, "用户信息修改成功");
        }
        return new ResponseUtil().setErrorMsg(400, "用户信息修改失败");
        
    }
    
    @RequiresPermissions("market:mange:user:delete")
    @DeleteMapping("/user/delete/{id}")
    public ResponseData deleteUserInfo(@PathVariable Integer id) {
        boolean flag = userManageService.deleteUserByUserId(id);
        if(flag){
            return new ResponseUtil().setData(true, "该用户已删除");
        }
        return new ResponseUtil().setErrorMsg(400, "用户删除失败，请联系管理员");
    }
    
    /**
     * @description: 单个用户授权(动态授权)
     * @param:
     * @return:
     */
    @RequiresPermissions("market:manage:user:permission")
    @GetMapping("/user/permission")
    public ResponseData userDynamicPermission() {
        
        return new ResponseUtil().setData(true,"授权成功");
    }
    
    /**
     * @description: 权限接口（获取权限数据列表）
     * @param:
     * @return:
     */
    @GetMapping("/permission/list")
    public ResponseData selectPermissionList(HttpServletRequest request) {
        
        return new ResponseUtil().setData(null);
    }
}
