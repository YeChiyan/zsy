package com.cug.cs.overseaprojectinformationsystem.cotroller;

import com.cug.cs.overseaprojectinformationsystem.bean.common.*;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.Infiling;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.PageBean;
import com.cug.cs.overseaprojectinformationsystem.service.InfilingService;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * @author shentong
 * @date 2023/10/7 15:55
 * @description
 */
@RestController
@RequestMapping("/contract")
public class InfilingController {
    @Autowired
    private InfilingService infilingService;

    @RequiresPermissions("contract:infilings:list")
    @GetMapping("/infilings")
    public ResData getInfilingList(PageBaseInfo pageBaseInfo) {
        PageBean pageBean = infilingService.getAll(pageBaseInfo);
        return new ResUtil<PageBean>().setData(pageBean, "success");
    }

    @RequiresPermissions("contract:infilings:add")
    @PostMapping("/infilings")
    public ResponseData addInfiling(@RequestBody Infiling infiling) {
        infilingService.add(infiling);
        return new ResponseUtil<Infiling>().setData(infiling,"success");
    }

    @RequiresPermissions("contract:infilings:update")
    @PutMapping("/infilings")
    public ResponseData updateInfiling(@RequestBody Infiling infiling) {
        infilingService.update(infiling);
        return new ResponseUtil<>().setData(null,"message");
    }

    @RequiresPermissions("contract:infilings:delete")
    @DeleteMapping("/infilings")
    public ResponseData deleteInfiling(Integer id) {
        infilingService.delete(id);
        return new ResponseUtil<>().setData(null,"message");
    }

    @RequiresPermissions("contract:submit")
    @PostMapping("/submit")
    public int submitInfiling(@RequestBody Infiling infiling) {
        return infilingService.submitInfiling(infiling);
    }

    @RequiresPermissions("contract:pass")
    @PostMapping("/pass")
    public int infilingPass(Integer id) {
        return infilingService.infilingPass(id);
    }

    @RequiresPermissions("contract:reject")
    @PostMapping("/reject")
    public int infilingReject(Integer id) {
        return infilingService.infilingReject(id);
    }
}
