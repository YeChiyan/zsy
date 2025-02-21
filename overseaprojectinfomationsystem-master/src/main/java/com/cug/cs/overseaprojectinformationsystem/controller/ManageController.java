package com.cug.cs.overseaprojectinformationsystem.cotroller;

import com.cug.cs.overseaprojectinformationsystem.bean.common.*;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.Manage;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.PageBean;
import com.cug.cs.overseaprojectinformationsystem.dao.ManageExportDao;
import com.cug.cs.overseaprojectinformationsystem.service.ManageService;
import com.cug.cs.overseaprojectinformationsystem.util.ExcelUtil;
import com.cug.cs.overseaprojectinformationsystem.util.ManageExportUtil;
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
import java.util.List;

/**
 * @author shentong
 * @date 2023/10/7 20:22
 * @description
 */
@Slf4j
@RestController
@RequestMapping("/contract")
public class ManageController {

    @Autowired
    private ManageService manageService;

    @RequiresPermissions("contract:manages:list")
    @GetMapping("/manages")
    public ResData getManageList(PageBaseInfo pageBaseInfo) {
        PageBean pageBean = manageService.getAll(pageBaseInfo);
        return new ResUtil<PageBean>().setData(pageBean, "success");
    }

    @RequiresPermissions("contract:manages:add")
    @PostMapping("/manages")
    public ResponseData addManage(@RequestBody Manage manage) {
        manageService.add(manage);
        return new ResponseUtil<Manage>().setData(manage,"success");
    }

    @RequiresPermissions("contract:manages:update")
    @PutMapping("/manages")
    public ResponseData updateManage(@RequestBody Manage manage) {
        manageService.update(manage);
        return new ResponseUtil<>().setData(null,"message");
    }

    @RequiresPermissions("contract:manages:delete")
    @DeleteMapping("/manages")
    public ResponseData deleteManage(Integer id) {
        manageService.delete(id);
        return new ResponseUtil<>().setData(null,"message");
    }

    @Autowired
    ManageExportDao manageExportDao;
    @ResponseBody
    @RequestMapping("/exportexcel")
    public void manageExport(HttpServletResponse response) throws IOException {
        String fileName = "合同信息管理.xlsx";
        String[] sheetName = {"合同信息管理"};
        String[] title = {"合同管理序号","甲方","合同号","我方签约公司名称","我方合同签字人姓名","合同名称","工作性质","是否一体化项目","合同额","合同签订日期","合同起始日期","合同终止日期"};
        List<Manage> manageList = manageExportDao.selectList(null);
        String[][] content = new String[manageList.size()][title.length];
        log.info("——————————————————————准备工作完成——————————————————————");
        //导出合同管理表格
        for (int i = 0;i<manageList.size();i++){
            String[] row = content[i];
            Manage manage = manageList.get(i);
            row[0] = String.valueOf(manage.getId());
            row[1] = manage.getLessor();
            row[2] = String.valueOf(manage.getContractNum());
            row[3] = manage.getOurCompany();
            row[4] = manage.getOurSignatory();
            row[5] = manage.getProjectName();
            row[6] = ManageExportUtil.toType(manage.getWorkNature());
            row[7] = ManageExportUtil.toInt(manage.getIntegration());
            row[8] = String.valueOf(manage.getContractAmount());
            row[9] = String.valueOf(manage.getSignTime());
            row[10] = String.valueOf(manage.getStartTime());
            row[11] = String.valueOf(manage.getEndTime());
        }
        XSSFWorkbook workbook = ExcelUtil.getWorkbook(sheetName, title, content,true);
        log.info("-————————————————————数据已写入文件————————————————————-");
        // TODO 这里路径写死了，前端可以传一个路径进来，不同的用户路径是不同的
        String path = PathUtil.getPath()+fileName;
        log.info(path);

        FileOutputStream out = new FileOutputStream(new File(path));
        workbook.write(out);
        log.info("——————————————————————文件已输出——————————————————————");

        log.info("合同管理模块下载");
        try{
            URL url = new File(path).toURI().toURL();
            URLConnection conn = url.openConnection();
            InputStream inputStream = conn.getInputStream();
            log.info("111");
            response.reset();
            response.setContentType(conn.getContentType());
            String filename = "合同管理模块下载.xlsx";
            response.setHeader("Content-Disposition", "attachment; filename=" + URLEncoder.encode(filename, "UTF-8"));
            log.info("222");
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
