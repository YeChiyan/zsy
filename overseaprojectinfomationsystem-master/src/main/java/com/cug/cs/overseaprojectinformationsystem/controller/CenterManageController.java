package com.cug.cs.overseaprojectinformationsystem.cotroller;

import com.cug.cs.overseaprojectinformationsystem.bean.bo.CenterListVO;
import com.cug.cs.overseaprojectinformationsystem.bean.common.PageBaseInfo;
import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseData;
import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseUtil;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.Center;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.Member;
import com.cug.cs.overseaprojectinformationsystem.service.CenterManageService;
import com.cug.cs.overseaprojectinformationsystem.service.UserManageService;
import com.github.pagehelper.PageInfo;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * @description: TODO
 * @author: ShengHui
 * @date: 2023-09-24  13:44
 */
@RestController
@Slf4j
@RequestMapping("market/center")
public class CenterManageController {
    @Autowired
    CenterManageService centerManageService;
    @Autowired
    UserManageService userManageService;
    
    @RequiresPermissions("market:center:manage:list")
    @GetMapping("/manage/list")
    public ResponseData setectCenterList(HttpServletRequest request, PageBaseInfo pageBaseInfo) {
        PageInfo centerList = centerManageService.selectCenterList(pageBaseInfo);
        return new ResponseUtil().setData(centerList);
    }
    
    @RequiresPermissions("market:center:manage:list")
    @GetMapping("/manage/list/{id}")
    public ResponseData setectCenterListByCenterId(HttpServletRequest request, @PathVariable Integer id) {
        Center centerInfo = centerManageService.selectCenterInfoByCenterId(id);
        return new ResponseUtil().setData(centerInfo);
    }
    
    @RequiresPermissions("market:center:manage:create")
    @PostMapping("/manage/create")
    public ResponseData addCenter(HttpServletRequest request, @RequestBody Center center) {
        if (center.getRoleId() == null || center.getRoleId()[0] == 0) {
            Integer[] integers = new Integer[1];
            integers[0] = 2;
            center.setRoleId(integers);
        }
        boolean flag = centerManageService.insertNewCenter(center);
        if (flag == true) {
            return new ResponseUtil().setData(null);
        }
        return new ResponseUtil<>().setErrorMsg("新建分中心失败，请联系管理员");
    }
    
    @RequiresPermissions("market:center:manage:update")
    @GetMapping("/manage/update/{id}")
    public ResponseData updateCenterLByCenterId(HttpServletRequest request, @RequestBody Center center) {
        boolean flag = centerManageService.updateCenterInfo(center);
        if (flag) {
            return new ResponseUtil().setData("分中心数据已更新");
        }
        return new ResponseUtil().setErrorMsg("分中心数据更新失败，请联系管理员");
    }
    
    /**
     * @description: 删除分中心的时候需要发两个请求一个获取userList, 如果userList存在进行下一步
     * @param:
     * @return:
     */
    @RequiresPermissions("market:center:manage:delete")
    @GetMapping("/manage/delete")
    public ResponseData deleteCenterByCenterId(HttpServletRequest request, @PathVariable Integer id) {
        // 逻辑删除分中心前先确定，该分中心是否包含人员
        
        boolean flag = false;
        
        flag = centerManageService.deleteCenterInfo(id);
        if (flag) {
            return new ResponseUtil().setData("分中心数据已逻辑删除");
        }
        return new ResponseUtil().setData("分中心数据逻辑删除失败，请联系管理员");
        
    }
    
    /**
     * @description: 该方法获取center列表用于创建用户的时候进行选择
     * @param:
     * @return:
     */
    @GetMapping("manage/centerlist")
    public ResponseData selectCenterInfo(HttpServletRequest request) {
        List<CenterListVO> centerInfoList = centerManageService.selectCenterInfo();
        return new ResponseUtil().setData(centerInfoList);
    }
    
}
