package com.cug.cs.overseaprojectinformationsystem.cotroller;

import com.cug.cs.overseaprojectinformationsystem.bean.common.*;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.Outfiling;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.PageBean;
import com.cug.cs.overseaprojectinformationsystem.service.OutfilingService;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * @author shentong
 * @date 2023/10/7 20:05
 * @description
 */
@RestController
@RequestMapping("/contract")
public class OutfilingController {
    @Autowired
    private OutfilingService outfilingService;

    @RequiresPermissions("contract:outfilings:list")
    @GetMapping("/outfilings")
    public ResData getOutfilingList(PageBaseInfo pageBaseInfo) {
        PageBean pageBean = outfilingService.getAll(pageBaseInfo);
        return new ResUtil<PageBean>().setData(pageBean, "success");
    }

    @RequiresPermissions("contract:outfilings:add")
    @PostMapping("/outfilings")
    public ResponseData addOutfiling(@RequestBody Outfiling outfiling) {
        outfilingService.add(outfiling);
        return new ResponseUtil<Outfiling>().setData(outfiling,"success");
    }

    @RequiresPermissions("contract:outfilings:update")
    @PutMapping("/outfilings")
    public ResponseData updateOutfiling(@RequestBody Outfiling outfiling) {
        outfilingService.update(outfiling);
        return new ResponseUtil<>().setData(null,"message");
    }

    @RequiresPermissions("contract:outfilings:delete")
    @DeleteMapping("/outfilings")
    public ResponseData deleteOutfiling(Integer id) {
        outfilingService.delete(id);
        return new ResponseUtil<>().setData(null,"message");
    }

    @RequiresPermissions("contract:pass1")
    @PostMapping("/pass1")
    public int outfilingPass(Integer id) {
        return outfilingService.outfilingPass(id);
    }

    @RequiresPermissions("contract:reject1")
    @PostMapping("/reject1")
    public int outfilingReject(Integer id) {
        return outfilingService.outfilingReject(id);
    }
}
