package com.cug.cs.overseaprojectinformationsystem.cotroller;

import com.cug.cs.overseaprojectinformationsystem.bean.common.*;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.NewSign;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.PageBean;
import com.cug.cs.overseaprojectinformationsystem.dao.ExcelNewDao;
import com.cug.cs.overseaprojectinformationsystem.service.NewSignService;
import com.cug.cs.overseaprojectinformationsystem.util.ExcelUtil;
import com.cug.cs.overseaprojectinformationsystem.util.NewSignUtil;
import com.cug.cs.overseaprojectinformationsystem.util.PathUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.math.BigDecimal;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.List;
/**
 * @author shentong
 * @date 2023/9/18 18:10
 * @description 新签市场Controller
 */
@RestController
@Slf4j
@RequestMapping("/market")
public class NewSignController {
    @Autowired
    private NewSignService newSignService;

    @RequiresPermissions("market:newSigns:list")
    @GetMapping("/newSigns")
    public ResData getNewSignList(PageBaseInfo pageBaseInfo){
        PageBean pageBean = newSignService.getAll(pageBaseInfo);
        return new ResUtil<PageBean>().setData(pageBean,"success");
    }

    @RequiresPermissions("market:newSigns:add")
    @PostMapping("/newSigns")
    public ResponseData addNewSign(@RequestBody NewSign newSign) {
        newSignService.add(newSign);
        return new ResponseUtil<NewSign>().setData(newSign,"success");
    }

    @RequiresPermissions("market:newSigns:update")
    @PutMapping("/newSigns")
    public ResponseData updateNewSign(@RequestBody NewSign newSign) {
        newSignService.update(newSign);
        return new ResponseUtil<>().setData(null,"message");
    }

    @RequiresPermissions("market:newSigns:delete")
    @DeleteMapping("/newSigns")
    public ResponseData deleteNewSign(Integer id) {
        newSignService.delete(id);
        return new ResponseUtil<>().setData(null,"message");
    }

    @PostMapping("/newSignsByCenter")
    public ResData getNewSignListByCenter(@RequestBody PageBaseInfo pageBaseInfo){
        PageBean pageBean = newSignService.selectByCenter(pageBaseInfo);
        return new ResUtil<PageBean>().setData(pageBean,"success");
    }

    @Autowired
    ExcelNewDao excelNewDao;
    @ResponseBody
    @RequestMapping("/newsignexcel")
    public void newSignExport(HttpServletResponse response) throws IOException {
        String fileName = "新签市场.xlsx";
        String[] sheetName = {"新签市场"};
        String[] title = {"地区","国家","工区名称","甲方","我方签约公司名称","我方合同签字人姓名","项目名称","合同号","工作性质","是否一体化项目",
                "工区地表类型","是否PSTM","是否PSDM","工作量","新签合同额（万美元）","合同签订日期","合同关闭日期","备注"};
        List<NewSign> newSignList = excelNewDao.selectList(null);
        String[][] content = new String[newSignList.size()][title.length];
        log.info("——————————————————————准备工作完成——————————————————————");
        //导出新签市场
        for(int i = 0;i<newSignList.size();i++) {
            String[] row = content[i];
            NewSign newSign = newSignList.get(i);
            row[0] = newSign.getArea();
            row[1] = newSign.getCountry();
            row[2] = newSign.getWorkareaName();
            row[3] = newSign.getLessor();
            row[4] = newSign.getOurCompany();
            row[5] = newSign.getSignatoryName();
            row[6] = newSign.getProjectName();
            row[7] = String.valueOf(newSign.getContractNum());
            row[8] = newSign.getWorkNature();
            row[9] = NewSignUtil.toInt(newSign.getIntegration());
            row[10] = newSign.getSurfaceType();
            row[11] = NewSignUtil.toPstm(newSign.getPstm());
            row[12] = newSign.getPsdm();
            List<BigDecimal> workList = newSignService.getWorkload(newSign.getContractNum());
            row[13] = workList.get(0) +"km"+"+"+workList.get(1)+"sqkm";
            row[14] = String.valueOf(newSign.getContractAmount());
            row[15] = String.valueOf(newSign.getSignDate());
            row[16] = String.valueOf(newSign.getCloseDate());
            row[17] = newSign.getNote();
        }
        log.info("————————————————————新签市场导出完成————————————————————");

        XSSFWorkbook workbook = ExcelUtil.getWorkbook(sheetName, title, content,true);
        log.info("-————————————————————数据已写入文件————————————————————-");

        // TODO 这里路径写死了，前端可以传一个路径进来，不同的用户路径是不同的
        String path = PathUtil.getPath()+fileName;
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
            String filename = "新签市场.xlsx";
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
