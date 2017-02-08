package com.kk;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.kk.signing.SigningInformationUtil;
import com.kk.signing.SigningInformation;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.Base64;
import java.util.Enumeration;

/**
 * Servlet implementation class SignGenerator
 */
public class SignGenerator extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public SignGenerator() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		PrintWriter out = response.getWriter();
		out.println("this is a get request after bug fixes");
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		
		try {
			String passCert = request.getHeader("passCert");
			String passKey = request.getHeader("passKey");
			String caCert = request.getHeader("caCert");
			String manifestJSONString = request.getHeader("manifestJSON");
			byte[] manifestJSON = manifestJSONString.getBytes();
			//byte[] manifestJSON = Base64.getDecoder().decode(manifestJSONString);
			//byte[] manifestJSON = java.net.URLDecoder.decode(manifestJSONString, "UTF-8").getBytes();
			//InputStream passCertStream = new ByteArrayInputStream(passCert.getBytes("UTF-8"));
			InputStream passCertStream = new ByteArrayInputStream(Base64.getDecoder().decode(passCert));
			//InputStream caCertStream = new ByteArrayInputStream(caCert.getBytes("UTF-8"));
			InputStream caCertStream = new ByteArrayInputStream(Base64.getDecoder().decode(caCert));

			SigningInformationUtil pu = new SigningInformationUtil();
			SigningInformation ps = new SigningInformation();
			ps = pu.loadSigningInformationFromPKCS12AndIntermediateCertificate(passCertStream, passKey, caCertStream);
			byte[] signature = pu.signManifest(manifestJSON, ps);
			
			//out.println("<p>the passCert is" + passCert + "</p>");
			//out.println("<p>the passKey is" + passKey + "</p>");
			//out.println("<p>the caCert is" + caCert + "</p>");
			//out.println("<p>the signature is" + sb.toString()
			//		+ "</p>");
			response.setContentType("application/octet-stream");
			ServletOutputStream stream = response.getOutputStream();
			stream.write(signature);
			stream.close();
			//out.println(new String(signature));
		} catch (Exception e) {
			PrintWriter out = response.getWriter();
			out.println("Error is " + e.getMessage());
			out.println("Error is " + e.getStackTrace().toString());
		}
		/*
		 * PKInMemorySigningUtil pm = new PKInMemorySigningUtil(); byte[]
		 * signature = pm.signManifestFile(manifestJSON, ps); out.println(new
		 * String(signature));
		 */

	}

}
