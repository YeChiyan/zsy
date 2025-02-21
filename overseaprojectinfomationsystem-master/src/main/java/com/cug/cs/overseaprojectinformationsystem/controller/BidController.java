package com.cug.cs.overseaprojectinformationsystem.cotroller;


import com.cug.cs.overseaprojectinformationsystem.bean.common.*;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.Bid;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.PageBean;
import com.cug.cs.overseaprojectinformationsystem.dao.ExcelBidDao;
import com.cug.cs.overseaprojectinformationsystem.service.BidService;
import com.cug.cs.overseaprojectinformationsystem.util.BidWayUtil;
import com.cug.cs.overseaprojectinformationsystem.util.CenterNameutil;
import com.cug.cs.overseaprojectinformationsystem.util.ExcelUtil;
import com.cug.cs.overseaprojectinformationsystem.util.PathUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

/**
 * @author shentong
 * @date 2023/9/18 18:10
 * @description 投标统计Controller
 */
@Slf4j
@RestController
@RequestMapping("/market")
public class BidController {
    @Autowired
    private BidService bidService;

    @RequiresPermissions("market:bids:list")
    @GetMapping("/bids")
    public ResData getBidsList(PageBaseInfo pageBaseInfo){
        PageBean pageBean = bidService.getAll(pageBaseInfo);
        return new ResUtil<PageBean>().setData(pageBean,"success");
    }

    @RequiresPermissions("market:bids:add")
    @PostMapping("/bids")
    public ResponseData addBid(@RequestBody Bid bid) {
        bidService.add(bid);
        return new ResponseUtil<Bid>().setData(bid,"success");
    }

    @RequiresPermissions("market:bids:update")
    @PutMapping("/bids")
    public ResponseData updateBid(@RequestBody Bid bid) {
        bidService.update(bid);
        return new ResponseUtil<>().setData(null,"message");
    }

    @RequiresPermissions("market:bids:delete")
    @DeleteMapping("/bids")
    public ResponseData deleteBid(Integer id) {
        bidService.delete(id);
        return new ResponseUtil<>().setData(null,"message");
    }


    //    文件导出
    @Autowired
    ExcelBidDao excelBidDao;
    @ResponseBody
    @RequestMapping("/bidexcel")
    public void bidExport(HttpServletResponse response) throws IOException {
        String fileName = "投标统计.xlsx";
        String[] sheetName = {"投标统计"};
        String[] title = {"序号","地区","国家","甲方","项目名称","邀标时间","闭标时间","业务类别","投标主体","是否总部支持",
                "招标方式","评标动态","中/落/弃标时间","落/弃标原因","预计合同额（万美元）","工作量","单价",
                "总价","是否一体化","备注（请标注汇率）"};
        List<Bid> bidList = excelBidDao.selectList(null);
        String[][] content = new String[bidList.size()][title.length];

        //导出投标项目
        for(int i = 0;i<bidList.size();i++){
            String[] row = content[i];
            Bid bid = bidList.get(i);
            row[0] = String.valueOf(bid.getId());
            row[1] = bid.getArea();
            row[2] = bid.getCountry();
            row[3] = bid.getLessor();
            row[4] = bid.getProjectName();
            row[5] = String.valueOf(bid.getInviteTime());
            row[6] = String.valueOf(bid.getCloseTime());
            row[7] = BidWayUtil.toType(bid.getBusidateType());
            row[8] = bid.getTenderBody();
            row[9] = BidWayUtil.toSupport(bid.getSupport());
            row[10] = BidWayUtil.toMethod(bid.getTenderMethod());
            row[11] = BidWayUtil.toDynamics(bid.getEvaDynamics());
            row[12] = String.valueOf(bid.getDate());
            row[13] = bid.getReason();
            row[14] = String.valueOf(bid.getAmount());
            row[15] = String.valueOf(bid.getWorkload());
            row[16] = String.valueOf(bid.getUnivalent());
            row[17] = String.valueOf(bid.getPrive());
            row[18] = BidWayUtil.toInt(bid.getIntegration());
            row[19] = bid.getNote();
        }
        log.info("————————————————————投标项目导出完成————————————————————");

        XSSFWorkbook workbook = ExcelUtil.getWorkbook(sheetName, title, content,true);
        log.info("-————————————————————数据已写入文件————————————————————-");

        // TODO 这里路径写死了，前端可以传一个路径进来，不同的用户路径是不同的
        String path = PathUtil.getPath() +fileName;
        log.info(path);

        FileOutputStream out = new FileOutputStream(new File(path));
        workbook.write(out);
        log.info("——————————————————————文件已输出——————————————————————");

        try{
            URL url = new File(path).toURI().toURL();
            URLConnection conn = url.openConnection();
            InputStream inputStream = conn.getInputStream();
            response.reset();
            response.setContentType(conn.getContentType());
            String filename = "投标统计.xlsx";
            response.setHeader("Content-Disposition", "attachment; filename=" + URLEncoder.encode(filename, "UTF-8"));
            byte[] buffer = new byte[1024];
            int len;
            OutputStream outputStream = response.getOutputStream();
            while ((len = inputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, len);
            }
            inputStream.close();
        }
        catch (IOException e){
            throw new IOException(e);
        }
    }

}
